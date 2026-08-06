"""
On-demand EyeWitness integration.

For a stored scan we build a list of web URLs (from open http/https-ish ports),
run EyeWitness against them in a background thread, then map the produced
screenshots back to hosts/ports and store them so the UI can show them.

EyeWitness is auto-detected in this order:
  1. $EYEWITNESS_PYTHON + $EYEWITNESS_SCRIPT (explicit override)
  2. a sibling checkout:  ../EyeWitness/eyewitness-venv/bin/python
                          ../EyeWitness/Python/EyeWitness.py
  3. an `eyewitness` binary on PATH
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from backend import db

BASE = Path(__file__).resolve().parent.parent
EW_OUTPUT_ROOT = BASE / "data" / "eyewitness"

# Ports we treat as "web" even when nmap didn't label the service http.
WEB_PORTS = {80, 81, 443, 591, 2082, 2087, 2095, 3000, 5000, 7001, 8000, 8008,
             8080, 8081, 8082, 8088, 8180, 8443, 8444, 8834, 8888, 9000, 9080,
             9090, 9443, 10000}
HTTPS_PORTS = {443, 8443, 8444, 9443, 10000}

# In-memory run status: scan_id -> {...}
_status: dict[int, dict] = {}
# Targets for an in-flight *agent* run: scan_id -> [{ip, port, url}]
_agent_targets: dict[int, list] = {}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_eyewitness() -> list[str] | None:
    py = os.environ.get("EYEWITNESS_PYTHON")
    script = os.environ.get("EYEWITNESS_SCRIPT")
    if py and script and Path(py).exists() and Path(script).exists():
        return [py, script]

    sib = BASE.parent / "EyeWitness"
    py2 = sib / "eyewitness-venv" / "bin" / "python"
    script2 = sib / "Python" / "EyeWitness.py"
    if py2.exists() and script2.exists():
        return [str(py2), str(script2)]

    binp = shutil.which("eyewitness")
    if binp:
        return [binp]
    return None


def is_available() -> bool:
    return find_eyewitness() is not None


def purge(scan_id: int) -> None:
    """Remove on-disk screenshot output for one scan."""
    shutil.rmtree(EW_OUTPUT_ROOT / str(scan_id), ignore_errors=True)
    (EW_OUTPUT_ROOT / f"urls-{scan_id}.txt").unlink(missing_ok=True)


def purge_all() -> None:
    """Remove all on-disk screenshot output."""
    shutil.rmtree(EW_OUTPUT_ROOT, ignore_errors=True)


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

def build_targets(scan: dict) -> list[dict]:
    """Return [{ip, port, url}] for web-ish open ports of up hosts."""
    targets = []
    for host in scan.get("hosts", []):
        if host.get("state") not in ("up", "", None):
            continue
        ip = host.get("ip", "")
        if not ip:
            continue
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            portid = int(p.get("portid", 0) or 0)
            svc = (p.get("service") or "").lower()
            tunnel = (p.get("tunnel") or "").lower()
            is_web = ("http" in svc) or (portid in WEB_PORTS) or (tunnel == "ssl")
            if not is_web:
                continue
            https = (tunnel == "ssl") or ("https" in svc) or (portid in HTTPS_PORTS)
            scheme = "https" if https else "http"
            targets.append({"ip": ip, "port": portid, "url": f"{scheme}://{ip}:{portid}"})
    return targets


# ---------------------------------------------------------------------------
# Screenshot → host/port mapping
# ---------------------------------------------------------------------------

def _match_screenshot(png: Path, targets: list[dict]) -> dict | None:
    """Best-effort map a screenshot filename back to a target (ip, port)."""
    stem = png.stem  # e.g. "127.0.0.1_631" or "10.0.0.5" (port 80/443 stripped)
    # normalise separators to help matching
    norm = stem.replace(":", "_").replace(".png", "")
    best = None
    for t in targets:
        ip = t["ip"]
        port = str(t["port"])
        if ip not in norm:
            continue
        # exact ip_port, or ip alone for default web ports
        if re.search(rf"(^|[^0-9]){re.escape(port)}([^0-9]|$)", norm):
            return t
        if t["port"] in (80, 443) and norm.strip("._") == ip:
            best = t
    return best


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_status(scan_id: int) -> dict:
    with _lock:
        return dict(_status.get(scan_id, {"state": "idle"}))


def _set_status(scan_id: int, **kw) -> None:
    with _lock:
        cur = _status.get(scan_id, {})
        cur.update(kw)
        _status[scan_id] = cur


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def start(scan_id: int) -> dict:
    """Kick off a background EyeWitness run for a scan. Returns current status."""
    with _lock:
        st = _status.get(scan_id)
        if st and st.get("state") == "running":
            return dict(st)
    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError("Scan not found.")
    ew = find_eyewitness()
    if not ew:
        _set_status(scan_id, state="error",
                    message="EyeWitness not found. Set EYEWITNESS_PYTHON/EYEWITNESS_SCRIPT "
                            "or place it at ../EyeWitness/.")
        return get_status(scan_id)

    targets = build_targets(scan)
    _set_status(scan_id, state="running", message="Starting EyeWitness…",
                total=len(targets), count=0, started_at=_now())

    t = threading.Thread(target=_run, args=(scan_id, targets, ew), daemon=True)
    t.start()
    return get_status(scan_id)


def _run(scan_id: int, targets: list[dict], ew: list[str]) -> None:
    try:
        if not targets:
            db.replace_screenshots(scan_id, [])
            _set_status(scan_id, state="done", message="No web services (http/https) found in this scan.",
                        total=0, count=0, finished_at=_now())
            return

        outdir = EW_OUTPUT_ROOT / str(scan_id)
        if outdir.exists():
            shutil.rmtree(outdir, ignore_errors=True)
        EW_OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

        # IMPORTANT: EyeWitness recreates the -d directory at startup, so the URL
        # list must live OUTSIDE it or it gets wiped before EyeWitness reads it.
        urls_file = EW_OUTPUT_ROOT / f"urls-{scan_id}.txt"
        urls_file.write_text("\n".join(t["url"] for t in targets) + "\n")

        cmd = ew + ["--web", "-f", str(urls_file), "-d", str(outdir), "--no-prompt"]
        _set_status(scan_id, message=f"Screenshotting {len(targets)} web service(s)…")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

        screens_dir = outdir / "screens"
        pngs = sorted(screens_dir.glob("*.png")) if screens_dir.exists() else []

        _store_screenshots(scan_id, targets, pngs)

        if not pngs:
            tail = (proc.stdout or "")[-800:] + (proc.stderr or "")[-800:]
            _set_status(scan_id, state="error", count=0, total=len(targets),
                        message="EyeWitness ran but produced no screenshots. "
                                "Check that chromium + chromedriver are installed.",
                        detail=tail.strip(), finished_at=_now())
            return

        _set_status(scan_id, state="done", count=len(pngs), total=len(targets),
                    message=f"Captured {len(pngs)} screenshot(s).", finished_at=_now())
    except subprocess.TimeoutExpired:
        _set_status(scan_id, state="error", message="EyeWitness timed out (30 min).",
                    finished_at=_now())
    except Exception as exc:  # noqa: BLE001
        _set_status(scan_id, state="error", message=f"EyeWitness failed: {exc}",
                    finished_at=_now())


def _store_screenshots(scan_id: int, targets: list[dict], pngs: list[Path]) -> int:
    """Map produced PNGs back to (ip, port) targets and persist them."""
    rows = []
    for png in pngs:
        t = _match_screenshot(png, targets)
        rows.append({
            "ip": t["ip"] if t else "",
            "port": t["port"] if t else 0,
            "url": t["url"] if t else "",
            "filename": str(png.resolve()),
        })
    db.replace_screenshots(scan_id, rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Remote agent runs
#
# The server dispatches the URL list to an agent over the WebSocket; the agent
# runs EyeWitness on its side and streams the PNGs back. These helpers own the
# status + on-disk output for that flow (called from agenthub).
# ---------------------------------------------------------------------------

def prepare_agent_run(scan_id: int, agent_uid: str) -> list[dict]:
    """Reset output, mark the run as dispatched, and return the web targets."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError("Scan not found.")
    targets = build_targets(scan)

    outdir = EW_OUTPUT_ROOT / str(scan_id)
    shutil.rmtree(outdir, ignore_errors=True)
    (outdir / "screens").mkdir(parents=True, exist_ok=True)

    with _lock:
        _agent_targets[scan_id] = targets
    _set_status(scan_id, state="running", message="Dispatched to agent…",
                total=len(targets), count=0, started_at=_now(), where="agent")
    return targets


def agent_no_targets(scan_id: int) -> None:
    db.replace_screenshots(scan_id, [])
    _set_status(scan_id, state="done", total=0, count=0,
                message="No web services (http/https) found in this scan.",
                finished_at=_now())


def agent_started(scan_id: int, total: int) -> None:
    _set_status(scan_id, message=f"Agent screenshotting {total} web service(s)…",
                total=total)


def agent_shot(scan_id: int, name: str, data: bytes) -> None:
    """Persist one screenshot streamed back from an agent."""
    screens = EW_OUTPUT_ROOT / str(scan_id) / "screens"
    screens.mkdir(parents=True, exist_ok=True)
    safe = os.path.basename(name or "").strip() or f"shot-{len(list(screens.glob('*.png'))) + 1}.png"
    if not safe.lower().endswith(".png"):
        safe += ".png"
    (screens / safe).write_bytes(data)
    with _lock:
        cur = _status.get(scan_id, {})
        cur["count"] = cur.get("count", 0) + 1


def agent_done(scan_id: int) -> None:
    with _lock:
        targets = _agent_targets.pop(scan_id, [])
    screens = EW_OUTPUT_ROOT / str(scan_id) / "screens"
    pngs = sorted(screens.glob("*.png")) if screens.exists() else []
    if not pngs:
        _set_status(scan_id, state="error", count=0,
                    message="Agent ran EyeWitness but returned no screenshots.",
                    finished_at=_now())
        return
    n = _store_screenshots(scan_id, targets, pngs)
    _set_status(scan_id, state="done", count=n,
                message=f"Captured {n} screenshot(s) via agent.", finished_at=_now())


def agent_error(scan_id: int, message: str, detail: str = "") -> None:
    with _lock:
        _agent_targets.pop(scan_id, None)
    _set_status(scan_id, state="error",
                message=message or "Agent EyeWitness error.",
                detail=(detail or "").strip(), finished_at=_now())
