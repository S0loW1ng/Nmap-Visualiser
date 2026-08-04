"""
Scan jobs: run nmap (locally in a background thread) with live output + stop,
and turn the resulting XML into a new scan.

The same `ingest_xml` is used for results that come back from remote agents, so
local rescans and agent scans land in the database identically (as new scans
with source_type "rescan" / "agent").

Security: user-supplied flags are validated (no shell, no output/input-file
flags), the target is validated against a strict pattern, and nmap is always
invoked with an argv list — never a shell string. We force `-oX <tempfile>` so
the app controls where XML goes, and stream nmap's `-v` stdout for live output.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from backend import db, parsers

# job_id -> {"proc": Popen, "stop": bool}
_procs: dict[int, dict] = {}
_lock = threading.Lock()

_META_CHARS = set(";|&$`<>()\n\r\t")
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:]*$")
_FORBIDDEN_EXACT = {"-iL", "-iR", "--resume", "--datadir", "--stylesheet", "--webxml"}
_FORBIDDEN_PREFIX = ("-oN", "-oX", "-oG", "-oA", "-oS")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required.")
    if len(target) > 255:
        raise ValueError("Target is too long.")
    if target[0] == "-":
        raise ValueError("Target cannot start with '-'.")
    if " " in target or any(c in _META_CHARS for c in target):
        raise ValueError("Target contains invalid characters.")
    if not _TARGET_RE.match(target):
        raise ValueError("Target must be a hostname, IP, or CIDR.")
    return target


def validate_flags(flags: str) -> list[str]:
    try:
        toks = shlex.split(flags or "")
    except ValueError as exc:
        raise ValueError(f"Could not parse flags: {exc}")
    for t in toks:
        if any(c in _META_CHARS for c in t):
            raise ValueError(f"Flag '{t}' contains invalid characters.")
        if t in _FORBIDDEN_EXACT or any(t.startswith(p) for p in _FORBIDDEN_PREFIX):
            raise ValueError(f"Flag '{t}' is not allowed (output/input flags are managed for you).")
    return toks


def build_argv(target: str, flags: str, xml_path: str) -> list[str]:
    t = validate_target(target)
    toks = validate_flags(flags)
    return ["nmap", *toks, "-v", "--stats-every", "2s", "-oX", xml_path, t]


def preview_command(target: str, flags: str) -> str:
    """The command as it would run (validated), for display."""
    argv = build_argv(target, flags, "<out.xml>")
    return " ".join(argv)


# ---------------------------------------------------------------------------
# Result ingestion (shared by local runner and remote agents)
# ---------------------------------------------------------------------------

def ingest_xml(job_id: int, xml_bytes: bytes | str, target: str, source_label: str) -> int:
    parsed = parsers.parse_xml(xml_bytes)
    parsed["source_type"] = source_label

    job = db.get_job(job_id)
    parent = job.get("parent_scan_id") if job else None

    # Auto-merge into the scan this rescan was launched from (if it still exists),
    # preserving that scan's notes/checkmarks.
    if parent and db.get_scan(parent):
        summ = db.merge_result_into_scan(parent, parsed)
        db.update_job(job_id, status="done", finished_at=_now(), result_scan_id=parent)
        db.append_job_output(
            job_id,
            f"\n[+] Merged into scan #{parent}: "
            f"+{summ['added_hosts']} host(s), +{summ['added_ports']} new port(s), "
            f"{summ['updated_ports']} updated.\n")
        return parent

    name = f"{source_label} {target}"
    scan_id = db.insert_scan(parsed, name)
    db.update_job(job_id, status="done", finished_at=_now(), result_scan_id=scan_id)
    db.append_job_output(job_id,
                         f"\n[+] Parsed {len(parsed['hosts'])} host(s) → new scan #{scan_id}\n")
    return scan_id


# ---------------------------------------------------------------------------
# Local runner
# ---------------------------------------------------------------------------

def start_local(job_id: int) -> None:
    t = threading.Thread(target=_run_local, args=(job_id,), daemon=True)
    t.start()


def _run_local(job_id: int) -> None:
    job = db.get_job(job_id)
    if not job:
        return
    target, flags = job["target"], job["flags"]

    tmp = tempfile.NamedTemporaryFile(prefix=f"nmapviewer-job{job_id}-", suffix=".xml", delete=False)
    xml_path = tmp.name
    tmp.close()

    try:
        argv = build_argv(target, flags, xml_path)
    except ValueError as exc:
        db.update_job(job_id, status="error", error=str(exc), finished_at=_now())
        Path(xml_path).unlink(missing_ok=True)
        return

    db.update_job(job_id, status="running", started_at=_now())
    db.append_job_output(job_id, "$ " + " ".join(argv) + "\n\n")

    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        db.update_job(job_id, status="error", error="nmap not found on this machine.",
                      finished_at=_now())
        Path(xml_path).unlink(missing_ok=True)
        return

    with _lock:
        _procs[job_id] = {"proc": proc, "stop": False}

    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            db.append_job_output(job_id, line)
            with _lock:
                if _procs.get(job_id, {}).get("stop"):
                    break
        proc.wait()
    finally:
        with _lock:
            stopped = _procs.get(job_id, {}).get("stop", False)
            _procs.pop(job_id, None)

    if stopped:
        db.update_job(job_id, status="stopped", finished_at=_now())
        db.append_job_output(job_id, "\n[!] Scan stopped by user.\n")
        Path(xml_path).unlink(missing_ok=True)
        return

    try:
        xml = Path(xml_path).read_bytes()
        if not xml.strip():
            raise ValueError("nmap produced no XML (did it error above?).")
        ingest_xml(job_id, xml, target, "rescan")
    except Exception as exc:  # noqa: BLE001
        db.update_job(job_id, status="error",
                      error=f"Finished but could not parse results: {exc}",
                      finished_at=_now())
    finally:
        Path(xml_path).unlink(missing_ok=True)


def stop_job(job_id: int) -> bool:
    """Stop a locally-running job. Returns True if it was running here."""
    with _lock:
        entry = _procs.get(job_id)
        if entry:
            entry["stop"] = True
    if entry:
        try:
            entry["proc"].terminate()
        except ProcessLookupError:
            pass
        return True
    return False
