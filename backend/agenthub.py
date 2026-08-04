"""
Agent hub: manages agent-initiated WebSocket connections.

Agents dial IN to /ws/agent (firewall-friendly), authenticate with the shared
token, register, then receive `run`/`stop` messages and stream results back.
Job results are ingested through scanjobs.ingest_xml, exactly like local scans.

The hub lives in the server's asyncio loop. HTTP handlers that need to dispatch
to an agent are async and `await hub.dispatch(...)`.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from starlette.websockets import WebSocket, WebSocketDisconnect

from backend import db, scanjobs


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentHub:
    def __init__(self) -> None:
        self._agents: dict[str, WebSocket] = {}  # agent_uid -> ws

    # -- presence --------------------------------------------------------
    def online_uids(self) -> set[str]:
        return set(self._agents.keys())

    def is_online(self, uid: str) -> bool:
        return uid in self._agents

    # -- dispatch (called from async HTTP handlers) ----------------------
    async def dispatch(self, agent_uid: str, job_id: int, target: str, flags: str) -> None:
        ws = self._agents.get(agent_uid)
        if ws is None:
            raise RuntimeError("Agent is not connected.")
        await ws.send_json({"type": "run", "job_id": job_id, "target": target, "flags": flags})

    async def send_stop(self, agent_uid: str, job_id: int) -> bool:
        ws = self._agents.get(agent_uid)
        if ws is None:
            return False
        await ws.send_json({"type": "stop", "job_id": job_id})
        return True

    # -- connection handler ---------------------------------------------
    async def handle(self, ws: WebSocket) -> None:
        token = ws.query_params.get("token", "")
        if token != db.get_or_create_agent_token():
            await ws.close(code=4401)
            return
        await ws.accept()

        uid = None
        try:
            reg = await ws.receive_json()
            if reg.get("type") != "register" or not reg.get("agent_uid"):
                await ws.close(code=4400)
                return
            uid = reg["agent_uid"]
            db.upsert_agent(uid, reg.get("name", ""), reg.get("platform", ""),
                            reg.get("nmap_version", ""), reg.get("tags", ""))
            self._agents[uid] = ws
            await ws.send_json({"type": "registered"})

            while True:
                msg = await ws.receive_json()
                await self._on_message(uid, msg)
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001 - never let one agent crash the hub
            pass
        finally:
            if uid and self._agents.get(uid) is ws:
                self._agents.pop(uid, None)

    async def _on_message(self, uid: str, msg: dict) -> None:
        t = msg.get("type")
        if t == "heartbeat":
            db.touch_agent(uid)
        elif t == "job_started":
            db.update_job(int(msg["job_id"]), status="running", started_at=_now())
        elif t == "output":
            db.append_job_output(int(msg["job_id"]), str(msg.get("chunk", "")))
        elif t == "job_stopped":
            db.update_job(int(msg["job_id"]), status="stopped", finished_at=_now())
        elif t == "job_error":
            db.update_job(int(msg["job_id"]), status="error",
                          error=str(msg.get("error", "")), finished_at=_now())
        elif t == "job_done":
            jid = int(msg["job_id"])
            job = db.get_job(jid)
            target = job["target"] if job else ""
            try:
                await asyncio.to_thread(scanjobs.ingest_xml, jid, msg.get("xml", ""), target, "agent")
            except Exception as exc:  # noqa: BLE001
                db.update_job(jid, status="error",
                              error=f"Could not parse agent results: {exc}", finished_at=_now())


hub = AgentHub()
