# nmap-viewer

A clean web UI for reading nmap scans. Import an nmap `.xml` or `.gnmap` file
and browse hosts, ports, services, versions, and script output in a tidy
interface — with a place for notes, markdown export, and markdown import.

> **Status:** Phase 1 (viewer) **and** Phase 2 (rescan + remote agents) are
> implemented and working.

---

## Features (Phase 1)

- **Import** nmap `.xml` (`-oX`) or `.gnmap` (`-oG`) — multiple files at once.
- **Host table**: sortable (IP / hostname / state / open count / OS),
  live filter across IPs, hostnames, ports, services, and versions.
- **Host detail**: every port with protocol, state, service, product/version,
  and full **NSE script output**.
- **Notes**: per-scan and per-host, auto-saved as you type.
- **Export**:
  - **Report.md** — a full readable markdown document (per-host sections,
    ports, script output, notes).
  - **Table.md** — a compact one-row-per-open-port markdown table.
- **Import a markdown table** back in (round-trips with Table.md) so a teammate
  can share results as a table and you can visualise them.
- **EyeWitness (on demand)**: one button per scan screenshots its web services
  (http/https ports) and pulls the images back into the UI — a gallery on the
  scan plus per-host thumbnails, with a click-to-zoom lightbox. Requires
  EyeWitness + chromium + chromedriver (see below).
- **Merge** two or more scans by IP into a new scan (unions ports, tags each
  with which scan it came from, and flags mismatches).
- **Backup / Restore** the whole database as a portable JSON bundle — save all
  your scans (with notes and checkmarks) and restore or move them to another
  machine. Restore *appends*, so it never wipes what you already have.
- **Checkmark** each host as reviewed (persists), and rename/delete scans.
  Everything is stored locally in SQLite.

---

## Requirements

- Python 3.10+
- `nmap` (only needed to *produce* scan files; the viewer itself just parses them)

## Run

```bash
cd nmap-viewer
./run.sh
```

First run creates a virtualenv and installs dependencies, then serves the app at:

```
http://127.0.0.1:8770
```

To listen on all interfaces (e.g. view from another machine on your LAN):

```bash
HOST=0.0.0.0 PORT=8770 ./run.sh
```

Manual start (if you prefer):

```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8770
```

## Try it

Generate a scan and import it through the UI:

```bash
nmap -sV -oX myscan.xml 127.0.0.1
# then drag myscan.xml into the "＋ Import scan" button
```

A pre-made sample lives in [`sample-data/`](sample-data/) (`localhost.xml`,
`localhost.gnmap`).

---

## Project layout

```text
nmap-viewer/
├── run.sh                   # one-command launcher (creates venv on first run)
├── requirements.txt
├── backend/
│   ├── app.py               # FastAPI routes + serves the frontend
│   ├── parsers.py           # nmap XML + gnmap → common structure
│   ├── db.py                # SQLite storage (scans / hosts / ports / notes)
│   ├── markdown_export.py   # report + table export
│   └── markdown_import.py   # parse a markdown table back into a scan
├── frontend/
│   ├── index.html
│   ├── style.css            # clean dark UI
│   └── app.js               # vanilla JS, no build step
├── sample-data/             # example nmap output for testing
└── data/                    # SQLite db is created here at runtime
```

## API (used by the UI, also usable directly)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scans/import` | Upload an nmap `.xml`/`.gnmap` (multipart `file`) |
| POST | `/api/import/markdown` | Import a markdown table (`{name, text}`) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Full scan with hosts + ports |
| PATCH | `/api/scans/{id}` | Rename (`{name}`) |
| DELETE | `/api/scans/{id}` | Delete a scan |
| PUT | `/api/scans/{id}/notes` | Save scan notes (`{notes}`) |
| PUT | `/api/hosts/{id}/notes` | Save host notes (`{notes}`) |
| GET | `/api/scans/{id}/export/table` | Download Table.md |
| GET | `/api/scans/{id}/export/report` | Download Report.md |
| POST | `/api/scans/merge` | Merge scans by IP (`{scan_ids, name}`) |
| POST | `/api/scans/{id}/eyewitness` | Run EyeWitness on the scan's web services |
| GET | `/api/scans/{id}/eyewitness/status` | Poll run status |
| GET | `/api/scans/{id}/screenshots` | List captured screenshots |
| GET | `/api/screenshots/{id}` | Serve a screenshot PNG |
| GET | `/api/backup` | Download the whole DB as a JSON bundle |
| POST | `/api/restore` | Restore/append scans from a JSON bundle (multipart `file`) |

---

## EyeWitness setup

The **📷 EyeWitness** button on a scan screenshots its web services. It needs
EyeWitness plus a headless browser available on the machine running the viewer:

- **EyeWitness** — auto-detected if checked out next to this project at
  `../EyeWitness/` (with its `eyewitness-venv/`), or on `PATH` as `eyewitness`,
  or via `EYEWITNESS_PYTHON` + `EYEWITNESS_SCRIPT` environment variables.
- **chromium** and **chromedriver** (EyeWitness runs Chrome headless).

Check availability at `GET /api/eyewitness/available`. If it isn't installed,
the button reports the error in the UI rather than failing silently. Screenshots
are stored under `data/eyewitness/<scan_id>/` and served through the API.

## Notes on formats

- **XML is the richer source.** The greppable (`.gnmap`) format folds
  product+version together and can mangle version strings that contain commas
  (an nmap-format limitation), so prefer `-oX` when you can.
- Script (NSE) output is only present in XML from `-sC`/`--script` scans.

---

## Rescan & agents (Phase 2)

In a host's detail panel, the **Deeper scan** box lets you re-run nmap against
that host:

- Edit the **nmap flags**, then either **📋 Copy command** or **▶ Run scan**.
- Pick where it runs: **Local (this machine)** or any connected **agent**.
- Running opens a **live-output** window with the streaming nmap output and a
  **■ Stop** button. When it finishes, the result is parsed into a **new scan**
  (`source_type` `rescan` or `agent`) you can open, note, screenshot, or merge.

**Agents** let you scan from a machine that can reach the targets even when the
viewer runs elsewhere (agents dial **out** over WebSocket — firewall-friendly):

1. Click **⛓ Agents** in the sidebar → copy the **token** and **⤓ Download agent**.
2. On the other machine: `pip install websockets && python3 nmap_viewer_agent.py`
   (the download is pre-filled with this server's URL + token; override with
   `--server ws://HOST:8770/ws/agent --token … --name lab-box` if needed).
3. It appears under **Agents** (online), and becomes selectable in **Run on:**.

Safety: user flags are validated (no shell, no output/input-file flags), the
target is pattern-checked, and nmap is always run as an argv list — never a
shell string. `-oX` is forced to a managed temp file.

Endpoints: `POST /api/jobs` · `GET /api/jobs/{id}` · `POST /api/jobs/{id}/stop`
· `GET /api/agents` · `GET /api/agent-token` · `GET /api/agents/script` ·
`WS /ws/agent`.

---

## Security note

This tool parses nmap output and (in the rescan/agent feature) **executes nmap**
on the machine you choose — locally or on an agent host. Only scan machines and
networks you are authorised to scan. The agent token gates who can connect;
treat it like a credential.
