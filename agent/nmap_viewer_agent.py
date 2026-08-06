#!/usr/bin/env python3
"""
nmap-viewer agent.

Dials OUT to an nmap-viewer server over WebSocket, then runs nmap scan jobs the
server sends and streams the output (and final XML) back. Run this on a machine
that can reach your targets; results appear in the viewer as new scans.

Usage:
    pip install websockets
    python3 nmap_viewer_agent.py                       # uses the baked-in defaults
    python3 nmap_viewer_agent.py --server ws://HOST:8770/ws/agent --token TOKEN --name lab-box

Requires: python3, nmap on PATH, and the `websockets` package.
"""

import argparse
import asyncio
import base64
import glob
import json
import os
import pathlib
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid

# These two lines are rewritten by the server's "Download agent" button.
DEFAULT_SERVER = "ws://127.0.0.1:8770/ws/agent"
DEFAULT_TOKEN = "CHANGEME"

try:
    import websockets
except ImportError:
    print("This agent needs the 'websockets' package:  pip install websockets", file=sys.stderr)
    sys.exit(1)

_META = set(";|&$`<>()\n\r\t")
_FORBIDDEN_EXACT = {"-iL", "-iR", "--resume", "--datadir", "--stylesheet", "--webxml"}
_FORBIDDEN_PREFIX = ("-oN", "-oX", "-oG", "-oA", "-oS")


def nmap_version():
    try:
        out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.splitlines()[0] if out else ""
    except Exception:
        return ""


def find_eyewitness():
    """Locate EyeWitness on the agent host: env override, then a binary on PATH."""
    py = os.environ.get("EYEWITNESS_PYTHON")
    script = os.environ.get("EYEWITNESS_SCRIPT")
    if py and script and os.path.exists(py) and os.path.exists(script):
        return [py, script]
    binp = shutil.which("eyewitness")
    if binp:
        return [binp]
    return None


def agent_uid():
    p = pathlib.Path.home() / ".nmap-viewer-agent-id"
    try:
        if p.exists():
            return p.read_text().strip()
        uid = uuid.uuid4().hex
        p.write_text(uid)
        return uid
    except Exception:
        return uuid.uuid4().hex


def build_argv(target, flags, xml_path):
    target = (target or "").strip()
    if not target or target[0] == "-" or " " in target or any(c in _META for c in target):
        raise ValueError("invalid target")
    toks = shlex.split(flags or "")
    for t in toks:
        if any(c in _META for c in t) or t in _FORBIDDEN_EXACT or any(t.startswith(p) for p in _FORBIDDEN_PREFIX):
            raise ValueError("flag not allowed: " + t)
    return ["nmap", *toks, "-v", "--stats-every", "2s", "-oX", xml_path, target]


class Runner:
    def __init__(self):
        self.proc = None
        self.stop = False


runner = Runner()


async def run_job(ws, job_id, target, flags):
    runner.stop = False
    runner.proc = None
    fd, xml_path = tempfile.mkstemp(prefix="nmapviewer-agent-", suffix=".xml")
    os.close(fd)
    try:
        argv = build_argv(target, flags, xml_path)
    except ValueError as exc:
        await ws.send(json.dumps({"type": "job_error", "job_id": job_id, "error": str(exc)}))
        return

    await ws.send(json.dumps({"type": "job_started", "job_id": job_id}))
    await ws.send(json.dumps({"type": "output", "job_id": job_id,
                              "chunk": "$ " + " ".join(argv) + "\n\n"}))
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        await ws.send(json.dumps({"type": "job_error", "job_id": job_id,
                                  "error": "nmap not found on the agent host"}))
        _unlink(xml_path)
        return

    runner.proc = proc
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        await ws.send(json.dumps({"type": "output", "job_id": job_id,
                                  "chunk": line.decode(errors="replace")}))
    await proc.wait()

    if runner.stop:
        await ws.send(json.dumps({"type": "job_stopped", "job_id": job_id}))
    else:
        try:
            xml = pathlib.Path(xml_path).read_text(errors="replace")
            if not xml.strip():
                raise ValueError("nmap produced no XML")
            await ws.send(json.dumps({"type": "job_done", "job_id": job_id, "xml": xml}))
        except Exception as exc:
            await ws.send(json.dumps({"type": "job_error", "job_id": job_id,
                                      "error": "could not read XML: " + str(exc)}))
    _unlink(xml_path)
    runner.proc = None


async def run_eyewitness(ws, ew_id, urls):
    """Run EyeWitness against a URL list and stream the PNGs back to the server."""
    ew = find_eyewitness()
    if not ew:
        await ws.send(json.dumps({"type": "ew_error", "ew_id": ew_id,
                                  "error": "EyeWitness not found on the agent host"}))
        return
    urls = [u for u in (urls or []) if u]
    if not urls:
        await ws.send(json.dumps({"type": "ew_done", "ew_id": ew_id, "count": 0}))
        return

    tmpdir = tempfile.mkdtemp(prefix="nmapviewer-ew-")
    outdir = os.path.join(tmpdir, "out")
    # EyeWitness recreates -d at startup, so keep the URL list OUTSIDE it.
    urls_file = os.path.join(tmpdir, "urls.txt")
    with open(urls_file, "w") as f:
        f.write("\n".join(urls) + "\n")

    await ws.send(json.dumps({"type": "ew_started", "ew_id": ew_id, "total": len(urls)}))
    cmd = ew + ["--web", "-f", urls_file, "-d", outdir, "--no-prompt"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
    except FileNotFoundError:
        await ws.send(json.dumps({"type": "ew_error", "ew_id": ew_id,
                                  "error": "could not launch EyeWitness on the agent"}))
        shutil.rmtree(tmpdir, ignore_errors=True)
        return

    screens = os.path.join(outdir, "screens")
    pngs = sorted(glob.glob(os.path.join(screens, "*.png"))) if os.path.isdir(screens) else []
    for png in pngs:
        try:
            with open(png, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
        except Exception:
            continue
        await ws.send(json.dumps({"type": "ew_shot", "ew_id": ew_id,
                                  "name": os.path.basename(png), "data_b64": b64}))

    if not pngs:
        tail = (out or b"").decode(errors="replace")[-800:]
        await ws.send(json.dumps({"type": "ew_error", "ew_id": ew_id,
                                  "error": "EyeWitness produced no screenshots (check chromium/chromedriver)",
                                  "detail": tail}))
    else:
        await ws.send(json.dumps({"type": "ew_done", "ew_id": ew_id, "count": len(pngs)}))
    shutil.rmtree(tmpdir, ignore_errors=True)


def _unlink(path):
    try:
        os.unlink(path)
    except Exception:
        pass


async def heartbeat(ws):
    while True:
        await asyncio.sleep(20)
        try:
            await ws.send(json.dumps({"type": "heartbeat"}))
        except Exception:
            return


async def main():
    ap = argparse.ArgumentParser(description="nmap-viewer agent")
    ap.add_argument("--server", default=DEFAULT_SERVER, help="server ws URL, e.g. ws://host:8770/ws/agent")
    ap.add_argument("--token", default=DEFAULT_TOKEN, help="agent auth token")
    ap.add_argument("--name", default=platform.node() or "agent", help="display name")
    ap.add_argument("--tags", default="", help="comma-separated tags")
    args = ap.parse_args()

    uid = agent_uid()
    sep = "&" if "?" in args.server else "?"
    url = f"{args.server}{sep}token={args.token}"
    print(f"[*] nmap-viewer agent '{args.name}' (uid {uid[:8]}…) → {args.server}")

    while True:
        try:
            async with websockets.connect(url, max_size=None, ping_interval=20) as ws:
                await ws.send(json.dumps({
                    "type": "register", "agent_uid": uid, "name": args.name,
                    "platform": platform.platform(), "nmap_version": nmap_version(),
                    "tags": args.tags, "has_eyewitness": find_eyewitness() is not None,
                }))
                print("[+] connected and registered")
                hb = asyncio.create_task(heartbeat(ws))
                try:
                    async for raw in ws:
                        msg = json.loads(raw)
                        t = msg.get("type")
                        if t == "run":
                            asyncio.create_task(run_job(ws, msg["job_id"], msg["target"], msg.get("flags", "")))
                        elif t == "ew_run":
                            asyncio.create_task(run_eyewitness(ws, msg["ew_id"], msg.get("urls", [])))
                        elif t == "stop":
                            runner.stop = True
                            if runner.proc:
                                try:
                                    runner.proc.terminate()
                                except Exception:
                                    pass
                finally:
                    hb.cancel()
        except Exception as exc:
            print(f"[-] disconnected: {exc} — retrying in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] bye")
