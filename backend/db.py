"""
SQLite storage for nmap-viewer.

Schema:
  scans  (id, name, source_type, args, scanner_version, started_at,
          imported_at, notes)
  hosts  (id, scan_id, ip, hostname, state, os_name, os_accuracy, notes)
  ports  (id, host_id, portid, protocol, state, service, product, version,
          extrainfo, tunnel, scripts_json)

Notes live on both scans (scan-level notes) and hosts (per-host notes).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "nmap_viewer.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    args            TEXT DEFAULT '',
    scanner_version TEXT DEFAULT '',
    started_at      TEXT,
    imported_at     TEXT NOT NULL,
    notes           TEXT DEFAULT '',
    folder_id       INTEGER REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    hostname    TEXT DEFAULT '',
    state       TEXT DEFAULT '',
    os_name     TEXT DEFAULT '',
    os_accuracy INTEGER,
    notes       TEXT DEFAULT '',
    checked     INTEGER NOT NULL DEFAULT 0,
    flagged     INTEGER NOT NULL DEFAULT 0,
    extraports_json TEXT DEFAULT '[]',
    findings_json   TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    portid       INTEGER NOT NULL,
    protocol     TEXT DEFAULT '',
    state        TEXT DEFAULT '',
    service      TEXT DEFAULT '',
    product      TEXT DEFAULT '',
    version      TEXT DEFAULT '',
    extrainfo    TEXT DEFAULT '',
    tunnel       TEXT DEFAULT '',
    scripts_json TEXT DEFAULT '[]',
    notes        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS screenshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip         TEXT DEFAULT '',
    port       INTEGER DEFAULT 0,
    url        TEXT DEFAULT '',
    filename   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS agents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_uid    TEXT UNIQUE NOT NULL,
    name         TEXT DEFAULT '',
    platform     TEXT DEFAULT '',
    nmap_version TEXT DEFAULT '',
    tags         TEXT DEFAULT '',
    first_seen   TEXT,
    last_seen    TEXT,
    has_eyewitness INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS jobs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    agent          TEXT DEFAULT 'local',   -- 'local' or an agent_uid
    target         TEXT NOT NULL,
    flags          TEXT DEFAULT '',
    status         TEXT DEFAULT 'queued',  -- queued/running/done/stopped/error
    created_at     TEXT,
    started_at     TEXT,
    finished_at    TEXT,
    output         TEXT DEFAULT '',
    result_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    parent_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    error          TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_shots_scan ON screenshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive migrations for databases created by an older version."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    if "checked" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN checked INTEGER NOT NULL DEFAULT 0")
    if "flagged" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0")
    if "extraports_json" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN extraports_json TEXT DEFAULT '[]'")
    if "findings_json" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN findings_json TEXT DEFAULT '[]'")
    pcols = {row[1] for row in conn.execute("PRAGMA table_info(ports)").fetchall()}
    if "notes" not in pcols:
        conn.execute("ALTER TABLE ports ADD COLUMN notes TEXT DEFAULT ''")
    jcols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if jcols and "parent_scan_id" not in jcols:
        conn.execute("ALTER TABLE jobs ADD COLUMN parent_scan_id INTEGER")
    scols = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    if "folder_id" not in scols:
        conn.execute("ALTER TABLE scans ADD COLUMN folder_id INTEGER")
    acols = {row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()}
    if acols and "has_eyewitness" not in acols:
        conn.execute("ALTER TABLE agents ADD COLUMN has_eyewitness INTEGER NOT NULL DEFAULT 0")


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def insert_scan(parsed: dict, name: str) -> int:
    """Persist a parsed scan (from parsers.parse_*). Returns the new scan id."""
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans (name, source_type, args, scanner_version,
                                  started_at, imported_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                name,
                parsed.get("source_type", ""),
                parsed.get("args", ""),
                parsed.get("scanner_version", ""),
                parsed.get("started_at"),
                parsed.get("imported_at") or _now(),
                parsed.get("notes", ""),
            ),
        )
        scan_id = cur.lastrowid

        for host in parsed.get("hosts", []):
            hcur = conn.execute(
                """INSERT INTO hosts (scan_id, ip, hostname, state, os_name,
                                      os_accuracy, notes, checked, flagged,
                                      extraports_json, findings_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    host.get("ip", ""),
                    host.get("hostname", ""),
                    host.get("state", ""),
                    host.get("os_name", ""),
                    host.get("os_accuracy"),
                    host.get("notes", ""),
                    1 if host.get("checked") else 0,
                    1 if host.get("flagged") else 0,
                    json.dumps(host.get("extraports", [])),
                    json.dumps(host.get("findings", [])),
                ),
            )
            host_id = hcur.lastrowid
            for port in host.get("ports", []):
                conn.execute(
                    """INSERT INTO ports (host_id, portid, protocol, state, service,
                                          product, version, extrainfo, tunnel,
                                          scripts_json, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        host_id,
                        port.get("portid", 0),
                        port.get("protocol", ""),
                        port.get("state", ""),
                        port.get("service", ""),
                        port.get("product", ""),
                        port.get("version", ""),
                        port.get("extrainfo", ""),
                        port.get("tunnel", ""),
                        json.dumps(port.get("scripts", [])),
                        port.get("notes", ""),
                    ),
                )
        return scan_id


def _insert_port_row(conn: sqlite3.Connection, host_id: int, port: dict) -> None:
    conn.execute(
        """INSERT INTO ports (host_id, portid, protocol, state, service, product,
                              version, extrainfo, tunnel, scripts_json, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (host_id, port.get("portid", 0), port.get("protocol", ""), port.get("state", ""),
         port.get("service", ""), port.get("product", ""), port.get("version", ""),
         port.get("extrainfo", ""), port.get("tunnel", ""),
         json.dumps(port.get("scripts", [])), port.get("notes", "")),
    )


def merge_result_into_scan(parent_scan_id: int, result: dict) -> dict:
    """
    Fold a fresh scan result (parsed dict) into an existing scan, by IP, WITHOUT
    destroying user annotations:
      * existing host notes + checked  → kept
      * existing port notes            → kept
      * a port seen again with different service/version gets a '🔀 rescan' note
        appended to its scripts (old → new); its fields are refreshed
      * brand-new ports / hosts        → added
    Returns a small summary {added_hosts, added_ports, updated_ports}.
    """
    summary = {"added_hosts": 0, "added_ports": 0, "updated_ports": 0}
    with get_conn() as conn:
        # index parent
        phosts: dict[str, dict] = {}
        for hr in conn.execute("SELECT * FROM hosts WHERE scan_id=?", (parent_scan_id,)).fetchall():
            h = dict(hr)
            ports = {}
            for pr in conn.execute("SELECT * FROM ports WHERE host_id=?", (h["id"],)).fetchall():
                p = dict(pr)
                ports[(p["protocol"], p["portid"])] = p
            phosts[h["ip"]] = {"row": h, "ports": ports}

        for rhost in result.get("hosts", []):
            ip = rhost.get("ip", "")
            if not ip:
                continue

            if ip not in phosts:
                hcur = conn.execute(
                    """INSERT INTO hosts (scan_id, ip, hostname, state, os_name,
                                          os_accuracy, notes, checked)
                       VALUES (?, ?, ?, ?, ?, ?, '', 0)""",
                    (parent_scan_id, ip, rhost.get("hostname", ""), rhost.get("state", ""),
                     rhost.get("os_name", ""), rhost.get("os_accuracy")),
                )
                hid = hcur.lastrowid
                summary["added_hosts"] += 1
                for rp in rhost.get("ports", []):
                    _insert_port_row(conn, hid, rp)
                    summary["added_ports"] += 1
                continue

            phost = phosts[ip]
            hrow = phost["row"]
            hid = hrow["id"]

            # refresh host-level facts (never touch notes / checked)
            upd = {}
            if rhost.get("state") == "up" and hrow["state"] != "up":
                upd["state"] = "up"
            if rhost.get("hostname") and not hrow["hostname"]:
                upd["hostname"] = rhost["hostname"]
            if rhost.get("os_name") and (not hrow["os_name"]
                                         or (rhost.get("os_accuracy") or 0) > (hrow["os_accuracy"] or 0)):
                upd["os_name"] = rhost["os_name"]
                upd["os_accuracy"] = rhost.get("os_accuracy")
            if upd:
                cols = ", ".join(f"{k}=?" for k in upd)
                conn.execute(f"UPDATE hosts SET {cols} WHERE id=?", list(upd.values()) + [hid])

            for rp in rhost.get("ports", []):
                key = (rp.get("protocol", ""), int(rp.get("portid", 0) or 0))
                existing = phost["ports"].get(key)
                if existing is None:
                    _insert_port_row(conn, hid, rp)
                    summary["added_ports"] += 1
                    continue

                try:
                    scripts = json.loads(existing.get("scripts_json") or "[]")
                except json.JSONDecodeError:
                    scripts = []
                seen = {(s.get("id", ""), s.get("output", "")) for s in scripts}
                for s in rp.get("scripts", []):
                    k = (s.get("id", ""), s.get("output", ""))
                    if k not in seen:
                        seen.add(k)
                        scripts.append({"id": s.get("id", ""), "output": s.get("output", "")})

                # Prefer richer data: a rescan that didn't re-detect a field (e.g. a
                # bare -sT with no version) must not erase what a prior deeper scan found.
                new_state = rp.get("state") or existing.get("state", "")
                new_service = rp.get("service") or existing.get("service", "")
                new_product = rp.get("product") or existing.get("product", "")
                new_version = rp.get("version") or existing.get("version", "")
                new_extra = rp.get("extrainfo") or existing.get("extrainfo", "")
                new_tunnel = rp.get("tunnel") or existing.get("tunnel", "")

                old_sig = (existing.get("state", ""), existing.get("service", ""),
                           existing.get("product", ""), existing.get("version", ""))
                new_sig = (new_state, new_service, new_product, new_version)
                if old_sig != new_sig:
                    old = " ".join(x for x in old_sig if x)
                    new = " ".join(x for x in new_sig if x)
                    scripts.append({"id": "🔀 rescan",
                                    "output": f"updated by rescan {_now()[:19]}\n  was: {old}\n  now: {new}"})
                    summary["updated_ports"] += 1

                conn.execute(
                    """UPDATE ports SET state=?, service=?, product=?, version=?,
                                        extrainfo=?, tunnel=?, scripts_json=? WHERE id=?""",
                    (new_state, new_service, new_product, new_version, new_extra, new_tunnel,
                     json.dumps(scripts), existing["id"]),
                )
    return summary


def update_scan_notes(scan_id: int, notes: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE scans SET notes = ? WHERE id = ?", (notes, scan_id))
        return cur.rowcount > 0


def update_host_notes(host_id: int, notes: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE hosts SET notes = ? WHERE id = ?", (notes, host_id))
        return cur.rowcount > 0


def update_port_notes(port_id: int, notes: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE ports SET notes = ? WHERE id = ?", (notes, port_id))
        return cur.rowcount > 0


def update_host_checked(host_id: int, checked: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE hosts SET checked = ? WHERE id = ?", (1 if checked else 0, host_id)
        )
        return cur.rowcount > 0


def update_host_flagged(host_id: int, flagged: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE hosts SET flagged = ? WHERE id = ?", (1 if flagged else 0, host_id)
        )
        return cur.rowcount > 0


def rename_scan(scan_id: int, name: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE scans SET name = ? WHERE id = ?", (name, scan_id))
        return cur.rowcount > 0


def delete_scan(scan_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def delete_scans(ids: list[int]) -> int:
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    with get_conn() as conn:
        cur = conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", ids)
        return cur.rowcount


def delete_all_scans() -> int:
    with get_conn() as conn:
        n = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        conn.execute("DELETE FROM scans")   # cascades to hosts/ports/screenshots
        conn.execute("DELETE FROM jobs")    # jobs reference scans; clear for a clean slate
        return n


# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------

def create_folder(name: str) -> dict:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO folders (name, created_at) VALUES (?, ?)", (name, _now())
        )
        fid = cur.lastrowid
        row = conn.execute("SELECT * FROM folders WHERE id=?", (fid,)).fetchone()
        return dict(row)


def list_folders() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT f.*,
                      (SELECT COUNT(*) FROM scans s WHERE s.folder_id = f.id) AS scan_count
                 FROM folders f
                ORDER BY LOWER(f.name)"""
        ).fetchall()
        return [dict(r) for r in rows]


def rename_folder(folder_id: int, name: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE folders SET name=? WHERE id=?", (name, folder_id))
        return cur.rowcount > 0


def delete_folder(folder_id: int) -> bool:
    """Delete a folder; its scans become unfiled (folder_id = NULL). Scans are kept."""
    with get_conn() as conn:
        conn.execute("UPDATE scans SET folder_id = NULL WHERE folder_id = ?", (folder_id,))
        cur = conn.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
        return cur.rowcount > 0


def move_scans_to_folder(ids: list[int], folder_id: int | None) -> int:
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    if folder_id is not None:
        with get_conn() as conn:
            if not conn.execute("SELECT 1 FROM folders WHERE id=?", (folder_id,)).fetchone():
                raise ValueError("Folder not found.")
    placeholders = ",".join("?" for _ in ids)
    with get_conn() as conn:
        cur = conn.execute(
            f"UPDATE scans SET folder_id = ? WHERE id IN ({placeholders})",
            [folder_id] + ids,
        )
        return cur.rowcount


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def list_scans() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM hosts h WHERE h.scan_id = s.id) AS host_count,
                      (SELECT COUNT(*) FROM ports p
                         JOIN hosts h ON p.host_id = h.id
                        WHERE h.scan_id = s.id AND p.state = 'open') AS open_port_count
                 FROM scans s
                ORDER BY s.imported_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]


def _ports_for_host(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM ports WHERE host_id = ? ORDER BY protocol, portid", (host_id,)
    ).fetchall()
    ports = []
    for r in rows:
        d = dict(r)
        try:
            d["scripts"] = json.loads(d.pop("scripts_json") or "[]")
        except json.JSONDecodeError:
            d["scripts"] = []
        ports.append(d)
    return ports


def get_scan(scan_id: int) -> dict | None:
    with get_conn() as conn:
        srow = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not srow:
            return None
        scan = dict(srow)
        hosts = []
        hrows = conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        for hrow in hrows:
            host = dict(hrow)
            try:
                host["extraports"] = json.loads(host.pop("extraports_json", None) or "[]")
            except json.JSONDecodeError:
                host["extraports"] = []
            try:
                host["findings"] = json.loads(host.pop("findings_json", None) or "[]")
            except json.JSONDecodeError:
                host["findings"] = []
            host["ports"] = _ports_for_host(conn, host["id"])
            host["open_port_count"] = sum(1 for p in host["ports"] if p["state"] == "open")
            hosts.append(host)
        scan["hosts"] = hosts
        return scan


def replace_screenshots(scan_id: int, rows: list[dict]) -> None:
    """Replace all screenshots for a scan with the given rows."""
    with get_conn() as conn:
        conn.execute("DELETE FROM screenshots WHERE scan_id = ?", (scan_id,))
        for r in rows:
            conn.execute(
                """INSERT INTO screenshots (scan_id, ip, port, url, filename, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, r.get("ip", ""), r.get("port", 0), r.get("url", ""),
                 r.get("filename", ""), _now()),
            )


def list_screenshots(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, ip, port, url FROM screenshots WHERE scan_id = ? ORDER BY ip, port",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_screenshot(shot_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM screenshots WHERE id = ?", (shot_id,)).fetchone()
        return dict(row) if row else None


def export_all() -> dict:
    """A portable backup of every scan (full fidelity)."""
    scans = []
    for meta in list_scans():
        full = get_scan(meta["id"])
        if full:
            scans.append(full)
    return {
        "format": "nmap-viewer-backup",
        "version": 1,
        "exported_at": _now(),
        "scan_count": len(scans),
        "scans": scans,
    }


def import_bundle(bundle: dict) -> int:
    """Append every scan from a backup bundle. Returns the number imported."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("scans"), list):
        raise ValueError("Not a valid nmap-viewer backup (missing 'scans' list).")
    count = 0
    for scan in bundle["scans"]:
        if not isinstance(scan, dict):
            continue
        name = scan.get("name") or "restored scan"
        insert_scan(scan, name)  # preserves source_type/args/notes/hosts/ports/checked
        count += 1
    return count


def get_host(host_id: int) -> dict | None:
    with get_conn() as conn:
        hrow = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not hrow:
            return None
        host = dict(hrow)
        host["ports"] = _ports_for_host(conn, host_id)
        return host


# ---------------------------------------------------------------------------
# Meta / agent token
# ---------------------------------------------------------------------------

def get_meta(key: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None


def set_meta(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_or_create_agent_token() -> str:
    import secrets
    tok = get_meta("agent_token")
    if not tok:
        tok = secrets.token_urlsafe(24)
        set_meta("agent_token", tok)
    return tok


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

def upsert_agent(agent_uid: str, name: str, platform: str, nmap_version: str,
                 tags: str = "", has_eyewitness: bool = False) -> None:
    now = _now()
    ew = 1 if has_eyewitness else 0
    with get_conn() as conn:
        exists = conn.execute("SELECT 1 FROM agents WHERE agent_uid = ?", (agent_uid,)).fetchone()
        if exists:
            conn.execute(
                """UPDATE agents SET name=?, platform=?, nmap_version=?, tags=?,
                                     has_eyewitness=?, last_seen=? WHERE agent_uid=?""",
                (name, platform, nmap_version, tags, ew, now, agent_uid),
            )
        else:
            conn.execute(
                """INSERT INTO agents (agent_uid, name, platform, nmap_version, tags,
                                       has_eyewitness, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (agent_uid, name, platform, nmap_version, tags, ew, now, now),
            )


def touch_agent(agent_uid: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE agents SET last_seen=? WHERE agent_uid=?", (_now(), agent_uid))


def list_agents() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]


def get_agent(agent_uid: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_uid=?", (agent_uid,)).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def create_job(agent: str, target: str, flags: str, parent_scan_id: int | None = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO jobs (agent, target, flags, status, created_at, output, parent_scan_id)
               VALUES (?, ?, ?, 'queued', ?, '', ?)""",
            (agent, target, flags, _now(), parent_scan_id),
        )
        return cur.lastrowid


def get_job(job_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None


def list_jobs(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, agent, target, flags, status, created_at, started_at,
                      finished_at, result_scan_id, error
                 FROM jobs ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_job(job_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [job_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE jobs SET {cols} WHERE id=?", vals)


def append_job_output(job_id: int, text: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE jobs SET output = COALESCE(output,'') || ? WHERE id=?", (text, job_id))
