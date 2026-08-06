"""
nmap-viewer -- FastAPI backend.

Phase 1 (viewer): import nmap XML/gnmap, browse hosts/ports, per-host and
per-scan notes, export markdown (report + table), import a markdown table back.

Run:
    uvicorn backend.app:app --host 0.0.0.0 --port 8770
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend import (
    agenthub,
    db,
    eyewitness_runner,
    markdown_export,
    markdown_import,
    merge,
    parsers,
    scanjobs,
)

AGENT_SCRIPT = Path(__file__).resolve().parent.parent / "agent" / "nmap_viewer_agent.py"

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="nmap-viewer", version="0.1.0")


@app.middleware("http")
async def revalidate_frontend(request: Request, call_next):
    """Force the browser to revalidate the UI assets so edits show up without a
    hard refresh (StaticFiles still answers 304 when nothing changed)."""
    resp = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class NotesBody(BaseModel):
    notes: str = ""


class CheckedBody(BaseModel):
    checked: bool = False


class FlaggedBody(BaseModel):
    flagged: bool = False


class RenameBody(BaseModel):
    name: str


class MarkdownImportBody(BaseModel):
    name: str = "Imported table"
    text: str
    folder_id: int | None = None


class MergeBody(BaseModel):
    scan_ids: list[int]
    name: str = ""


class JobBody(BaseModel):
    target: str
    flags: str = ""
    agent: str = "local"          # 'local' or an agent_uid
    parent_scan_id: int | None = None  # if set, auto-merge the result into this scan


class IdsBody(BaseModel):
    ids: list[int]


class FolderBody(BaseModel):
    name: str


class MoveBody(BaseModel):
    ids: list[int]
    folder_id: int | None = None   # None = unfiled (no folder)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def _assign_folder(scan_id: int, folder_id: int | None) -> None:
    """Best-effort move of a freshly imported scan into a folder (ignore bad ids)."""
    if folder_id is None:
        return
    try:
        db.move_scans_to_folder([scan_id], folder_id)
    except ValueError:
        pass


@app.post("/api/scans/import")
async def import_scan(file: UploadFile = File(...), folder_id: int | None = Form(None)):
    raw = await file.read()
    if not raw.strip():
        raise HTTPException(400, "Uploaded file is empty.")
    try:
        parsed = parsers.parse_auto(raw, file.filename or "")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Could not parse nmap output: {exc}")
    if not parsed.get("hosts"):
        raise HTTPException(400, "Parsed file contained no hosts.")
    name = (file.filename or "scan").rsplit("/", 1)[-1]
    scan_id = db.insert_scan(parsed, name)
    _assign_folder(scan_id, folder_id)
    return {"id": scan_id, "name": name, "source_type": parsed["source_type"],
            "host_count": len(parsed["hosts"])}


@app.post("/api/scans/import-merge")
async def import_merge(files: list[UploadFile] = File(...), name: str = Form(""),
                       folder_id: int | None = Form(None)):
    """Import several nmap files and merge them (by IP) into ONE new scan."""
    parsed_list = []
    skipped = []  # [{file, reason}]
    for f in files:
        fname = (f.filename or "scan").rsplit("/", 1)[-1]
        raw = await f.read()
        if not raw.strip():
            skipped.append({"file": fname, "reason": "empty file"})
            continue
        try:
            parsed = parsers.parse_auto(raw, f.filename or "")
        except Exception as exc:  # noqa: BLE001 - skip malformed, keep going
            skipped.append({"file": fname, "reason": str(exc)})
            continue
        if not parsed.get("hosts"):
            skipped.append({"file": fname, "reason": "no hosts found"})
            continue
        parsed["name"] = fname
        parsed_list.append(parsed)

    if not parsed_list:
        detail = "No valid nmap files with hosts were provided."
        if skipped:
            detail += " Skipped: " + "; ".join(f"{s['file']} ({s['reason']})" for s in skipped)
        raise HTTPException(400, detail)

    if len(parsed_list) == 1:
        p = parsed_list[0]
        final_name = name.strip() or p["name"]
        scan_id = db.insert_scan(p, final_name)
        _assign_folder(scan_id, folder_id)
        return {"id": scan_id, "name": final_name, "host_count": len(p["hosts"]),
                "merged_from": 1, "skipped": skipped}

    final_name = name.strip() or f"Merged import ({len(parsed_list)} files)"
    merged = merge.merge_scans(parsed_list, final_name)
    scan_id = db.insert_scan(merged, final_name)
    _assign_folder(scan_id, folder_id)
    return {"id": scan_id, "name": final_name, "host_count": len(merged["hosts"]),
            "merged_from": len(parsed_list), "skipped": skipped}


@app.post("/api/import/markdown")
def import_markdown(body: MarkdownImportBody):
    try:
        parsed = markdown_import.parse_markdown_table(body.text, body.name)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Could not parse markdown table: {exc}")
    if not parsed.get("hosts"):
        raise HTTPException(400, "No host rows found in the table.")
    scan_id = db.insert_scan(parsed, body.name)
    _assign_folder(scan_id, body.folder_id)
    return {"id": scan_id, "name": body.name, "host_count": len(parsed["hosts"])}


@app.post("/api/scans/merge")
def merge_scans(body: MergeBody):
    if len(body.scan_ids) < 2:
        raise HTTPException(400, "Select at least two scans to merge.")
    scans = []
    for sid in body.scan_ids:
        s = db.get_scan(sid)
        if not s:
            raise HTTPException(404, f"Scan {sid} not found.")
        scans.append(s)
    default_name = f"Merged ({len(scans)} scans)"
    name = (body.name or "").strip() or default_name
    parsed = merge.merge_scans(scans, name)
    if not parsed["hosts"]:
        raise HTTPException(400, "The selected scans contain no hosts to merge.")
    new_id = db.insert_scan(parsed, name)
    return {"id": new_id, "name": name, "host_count": len(parsed["hosts"])}


# ---------------------------------------------------------------------------
# Folders (organise scans)
# ---------------------------------------------------------------------------

@app.get("/api/folders")
def list_folders():
    return db.list_folders()


@app.post("/api/folders")
def create_folder(body: FolderBody):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Folder name cannot be empty.")
    return db.create_folder(name)


@app.patch("/api/folders/{folder_id}")
def rename_folder(folder_id: int, body: FolderBody):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Folder name cannot be empty.")
    if not db.rename_folder(folder_id, name):
        raise HTTPException(404, "Folder not found.")
    return {"ok": True}


@app.delete("/api/folders/{folder_id}")
def delete_folder(folder_id: int):
    if not db.delete_folder(folder_id):
        raise HTTPException(404, "Folder not found.")
    return {"ok": True}


@app.post("/api/scans/move")
def move_scans(body: MoveBody):
    try:
        n = db.move_scans_to_folder(body.ids, body.folder_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return {"moved": n}


@app.get("/api/scans")
def list_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


@app.patch("/api/scans/{scan_id}")
def rename_scan(scan_id: int, body: RenameBody):
    if not db.rename_scan(scan_id, body.name):
        raise HTTPException(404, "Scan not found.")
    return {"ok": True}


@app.post("/api/scans/delete")
def delete_scans(body: IdsBody):
    for sid in body.ids:
        eyewitness_runner.purge(sid)
    n = db.delete_scans(body.ids)
    return {"deleted": n}


@app.post("/api/scans/delete-all")
def delete_all_scans():
    n = db.delete_all_scans()
    eyewitness_runner.purge_all()
    return {"deleted": n}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int):
    if not db.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    eyewitness_runner.purge(scan_id)
    return {"ok": True}


@app.put("/api/scans/{scan_id}/notes")
def set_scan_notes(scan_id: int, body: NotesBody):
    if not db.update_scan_notes(scan_id, body.notes):
        raise HTTPException(404, "Scan not found.")
    return {"ok": True}


@app.put("/api/hosts/{host_id}/notes")
def set_host_notes(host_id: int, body: NotesBody):
    if not db.update_host_notes(host_id, body.notes):
        raise HTTPException(404, "Host not found.")
    return {"ok": True}


@app.put("/api/hosts/{host_id}/checked")
def set_host_checked(host_id: int, body: CheckedBody):
    if not db.update_host_checked(host_id, body.checked):
        raise HTTPException(404, "Host not found.")
    return {"ok": True}


@app.put("/api/hosts/{host_id}/flagged")
def set_host_flagged(host_id: int, body: FlaggedBody):
    if not db.update_host_flagged(host_id, body.flagged):
        raise HTTPException(404, "Host not found.")
    return {"ok": True}


@app.put("/api/ports/{port_id}/notes")
def set_port_notes(port_id: int, body: NotesBody):
    if not db.update_port_notes(port_id, body.notes):
        raise HTTPException(404, "Port not found.")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/export/table", response_class=PlainTextResponse)
def export_table(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return PlainTextResponse(
        markdown_export.to_table(scan),
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-table.md"'},
        media_type="text/markdown",
    )


@app.get("/api/scans/{scan_id}/export/report", response_class=PlainTextResponse)
def export_report(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return PlainTextResponse(
        markdown_export.to_report(scan),
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.md"'},
        media_type="text/markdown",
    )


# ---------------------------------------------------------------------------
# EyeWitness (on-demand screenshots of a scan's web services)
# ---------------------------------------------------------------------------

@app.get("/api/eyewitness/available")
def eyewitness_available():
    return {"available": eyewitness_runner.is_available()}


@app.post("/api/scans/{scan_id}/eyewitness")
async def run_eyewitness(scan_id: int, agent: str = "local"):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Scan not found.")

    agent = (agent or "local").strip()
    if agent == "local":
        try:
            return eyewitness_runner.start(scan_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))

    # Remote agent: dispatch the URL list; the agent streams screenshots back.
    if not agenthub.hub.is_online(agent):
        raise HTTPException(400, "That agent is not connected.")
    try:
        targets = eyewitness_runner.prepare_agent_run(scan_id, agent)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    if not targets:
        eyewitness_runner.agent_no_targets(scan_id)
        return eyewitness_runner.get_status(scan_id)
    try:
        await agenthub.hub.dispatch_eyewitness(agent, scan_id, [t["url"] for t in targets])
    except Exception as exc:  # noqa: BLE001
        eyewitness_runner.agent_error(scan_id, f"Could not dispatch to agent: {exc}")
        raise HTTPException(502, f"Could not dispatch to agent: {exc}")
    return eyewitness_runner.get_status(scan_id)


@app.get("/api/scans/{scan_id}/eyewitness/status")
def eyewitness_status(scan_id: int):
    return eyewitness_runner.get_status(scan_id)


@app.get("/api/scans/{scan_id}/screenshots")
def scan_screenshots(scan_id: int):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    return db.list_screenshots(scan_id)


@app.get("/api/screenshots/{shot_id}")
def screenshot_image(shot_id: int):
    shot = db.get_screenshot(shot_id)
    if not shot:
        raise HTTPException(404, "Screenshot not found.")
    path = Path(shot["filename"])
    if not path.exists():
        raise HTTPException(404, "Screenshot file missing on disk.")
    return FileResponse(str(path), media_type="image/png")


# ---------------------------------------------------------------------------
# Backup / restore (whole database as a portable JSON bundle)
# ---------------------------------------------------------------------------

@app.get("/api/backup")
def backup():
    bundle = db.export_all()
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="nmap-viewer-backup-{ts}.json"'},
    )


@app.post("/api/restore")
async def restore(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"Not valid JSON: {exc}")
    try:
        count = db.import_bundle(bundle)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"imported": count}


# ---------------------------------------------------------------------------
# Phase 2 — rescan jobs + remote agents
# ---------------------------------------------------------------------------

@app.get("/api/agent-token")
def agent_token():
    return {"token": db.get_or_create_agent_token()}


@app.get("/api/agents")
def list_agents():
    online = agenthub.hub.online_uids()
    agents = db.list_agents()
    for a in agents:
        a["online"] = a["agent_uid"] in online
    return agents


@app.get("/api/agents/script", response_class=PlainTextResponse)
def agent_script(request: Request, server: str = ""):
    """Return the agent script pre-filled with this server's ws URL + token."""
    if not AGENT_SCRIPT.exists():
        raise HTTPException(500, "Agent script template missing.")
    text = AGENT_SCRIPT.read_text()
    token = db.get_or_create_agent_token()
    if not server:
        host = request.headers.get("host", "127.0.0.1:8770")
        server = f"ws://{host}/ws/agent"
    text = re.sub(r'^DEFAULT_SERVER = ".*"$', f'DEFAULT_SERVER = "{server}"', text, flags=re.M)
    text = re.sub(r'^DEFAULT_TOKEN = ".*"$', f'DEFAULT_TOKEN = "{token}"', text, flags=re.M)
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": 'attachment; filename="nmap_viewer_agent.py"'},
        media_type="text/x-python",
    )


@app.post("/api/jobs")
async def create_job(body: JobBody):
    # validate up front so the user gets immediate feedback
    try:
        target = scanjobs.validate_target(body.target)
        scanjobs.validate_flags(body.flags)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    agent = (body.agent or "local").strip()
    if agent != "local" and not agenthub.hub.is_online(agent):
        raise HTTPException(400, "That agent is not connected.")

    parent = body.parent_scan_id if (body.parent_scan_id and db.get_scan(body.parent_scan_id)) else None
    job_id = db.create_job(agent, target, body.flags, parent_scan_id=parent)
    if agent == "local":
        scanjobs.start_local(job_id)
    else:
        try:
            await agenthub.hub.dispatch(agent, job_id, target, body.flags)
        except Exception as exc:  # noqa: BLE001
            db.update_job(job_id, status="error", error=f"Dispatch failed: {exc}")
            raise HTTPException(502, f"Could not dispatch to agent: {exc}")
    return db.get_job(job_id)


@app.get("/api/jobs")
def recent_jobs(limit: int = 50):
    return db.list_jobs(limit)


@app.get("/api/jobs/{job_id}")
def job_status(job_id: int):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    return job


@app.post("/api/jobs/{job_id}/stop")
async def stop_job(job_id: int):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    if scanjobs.stop_job(job_id):
        return {"ok": True, "where": "local"}
    if job["agent"] != "local":
        sent = await agenthub.hub.send_stop(job["agent"], job_id)
        return {"ok": sent, "where": "agent"}
    return {"ok": False, "message": "Job is not currently running."}


@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    await agenthub.hub.handle(websocket)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok\n"


# ---------------------------------------------------------------------------
# Frontend (mounted last so /api/* wins)
# ---------------------------------------------------------------------------

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
