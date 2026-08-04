# AGENT.md — Phase 2 design

> **Status: IMPLEMENTED.** Phase 2 (rescan + remote agents) is now built and
> tested. The design below is kept as reference; the shipped implementation
> follows it, with two pragmatic choices: the **browser** watches jobs via
> polling (`GET /api/jobs/{id}`) rather than a `/ws/ui` socket, and the URL list
> for a job is passed to the agent which runs nmap with `-v --stats-every 2s -oX`.
> Code: `backend/scanjobs.py`, `backend/agenthub.py`, `agent/nmap_viewer_agent.py`,
> jobs/agents/meta tables in `backend/db.py`, endpoints in `backend/app.py`.

---

## 1. What Phase 2 is

Two related capabilities from the original brief:

1. **Rescan** — from the viewer, re-run nmap against a host's IP/domain with
   **custom flags**, in a background thread, with a **Stop** control and **live
   output**. The result comes back into the viewer as a new scan.

2. **Remote agents** — the machine *viewing* results is often **not** the
   machine that can *reach the targets*. So the app can **generate lightweight
   agent scripts** that run on other machines. Each agent connects back to this
   app, receives scan jobs, runs nmap locally, streams output back live, and can
   be stopped. Results land in the viewer as new scans.

The viewer host itself counts as an agent target too ("local agent") so a
single-machine user still gets rescan without deploying anything.

---

## 2. Decisions already made (do not re-litigate)

These were chosen with the user up front:

- **UI:** web app (existing FastAPI backend + browser frontend). ✅ built in P1.
- **Agent transport:** **agent-initiated WebSocket.** The agent dials *out* to
  the server and holds the connection open. This is firewall/NAT-friendly (agent
  only needs outbound), and gives both **live output streaming** and **instant
  stop** on one channel.
- **Storage:** SQLite (existing).
- **Auth:** token-based. Each agent carries a shared/enrollment token; the server
  rejects unauthenticated sockets.
- **Results model:** an agent/rescan result is inserted as a **normal scan**
  via the existing `db.insert_scan(...)`, with `source_type` set to `"agent"` or
  `"rescan"`. Phase 1 was built so this slots in with no schema change to scans.

---

## 3. Proposed architecture

```
 Browser (viewer)            Server (this FastAPI app)              Agent host(s)
 ────────────────            ─────────────────────────              ─────────────
  Rescan button  ──POST──▶  create job (queued)                     nmap installed
  live output    ◀─WS────   ── job dispatched ──▶  WS  ◀──dial out── agent.py
  Stop button    ──POST──▶  ── stop signal ───▶                      runs nmap -oX -
                            ◀─ stdout chunks ──                      streams stdout
                            ◀─ final XML ─────   parse → insert_scan
```

- Agents connect to `wss://<server>/ws/agent?token=…` and register (name, os,
  nmap version, tags).
- The server keeps an in-memory registry of connected agents + a job queue.
- The browser watches job/agent state over a separate `/ws/ui` socket (or SSE),
  so live output appears without polling.

---

## 4. Data model additions (SQLite)

```sql
CREATE TABLE agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_uid   TEXT UNIQUE,      -- stable id the agent generates once
    name        TEXT,
    platform    TEXT,             -- linux / windows / mac
    nmap_version TEXT,
    tags        TEXT,             -- comma list, e.g. "dmz,lab"
    last_seen   TEXT,
    enrolled_at TEXT
);

CREATE TABLE jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    INTEGER REFERENCES agents(id),
    target      TEXT NOT NULL,    -- ip or domain
    flags       TEXT DEFAULT '',  -- user-supplied nmap flags (validated)
    status      TEXT DEFAULT 'queued',  -- queued/running/done/stopped/error
    created_at  TEXT,
    started_at  TEXT,
    finished_at TEXT,
    output      TEXT DEFAULT '',  -- accumulated stdout (live log)
    result_scan_id INTEGER REFERENCES scans(id),  -- set when parsed
    error       TEXT DEFAULT ''
);
```

`scans.source_type` gains values `"rescan"` and `"agent"`. No change to the
existing scans/hosts/ports tables otherwise.

---

## 5. WebSocket protocol (JSON messages)

**Agent → server**
- `{"type":"register","agent_uid","name","platform","nmap_version","tags"}`
- `{"type":"heartbeat"}`
- `{"type":"job_started","job_id"}`
- `{"type":"output","job_id","chunk":"…stdout…"}`
- `{"type":"job_done","job_id","xml":"<nmaprun>…"}`  (final `-oX -` payload)
- `{"type":"job_error","job_id","error":"…"}`

**Server → agent**
- `{"type":"run","job_id","target","flags"}`
- `{"type":"stop","job_id"}`   (agent kills the nmap subprocess)
- `{"type":"ack"}` / `{"type":"pong"}`

Server parses the final `xml` with the existing `parsers.parse_xml`, then
`db.insert_scan(parsed, name=f"rescan {target}")` and links `jobs.result_scan_id`.

---

## 6. HTTP endpoints to add

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/agents` | list registered/connected agents |
| POST | `/api/agents/enroll` | create an enrollment token |
| GET  | `/api/agents/{id}/script` | **download a ready-to-run agent script** filled with server URL + token |
| POST | `/api/jobs` | create a rescan job `{agent_id, target, flags}` |
| GET  | `/api/jobs/{id}` | job status + accumulated output |
| POST | `/api/jobs/{id}/stop` | request stop |
| WS   | `/ws/agent` | agent connection (token-authenticated) |
| WS   | `/ws/ui` | browser live updates (job output, agent presence) |

---

## 7. Agent script generator

`GET /api/agents/{id}/script` returns a **single-file Python agent** (stdlib +
`websockets`, or pure stdlib with `websocket-client` avoided) pre-filled with:
- the server WebSocket URL,
- the enrollment token,
- a generated `agent_uid`.

Agent responsibilities:
- dial the server, register, heartbeat;
- on `run`: spawn `nmap <flags> -oX - <target>` (validated), stream stdout
  chunks as `output`, send `job_done` with the final XML;
- on `stop`: terminate the subprocess (`proc.terminate()` / kill tree);
- reconnect with backoff if the socket drops.

Keep it dependency-light so it's easy to drop onto any box. Offer a
`--insecure`/`--server`/`--token` CLI override. Consider also emitting a tiny
shell one-liner and a Windows `.ps1` variant later.

---

## 8. Frontend additions

- **Per-host "Rescan" button** in the host detail panel → opens a modal:
  choose agent (default: local), enter/edit flags (prefill from the scan's
  original `args` if present, e.g. `-sCV -p-`), Run.
- **Live output panel**: streams stdout over `/ws/ui`, with a **Stop** button;
  on completion, links to the newly created scan.
- **Agents view**: list agents (online/offline, last seen, tags), an
  **"Add agent"** button that shows the enrollment token + **Download agent
  script** button, and copy-paste run instructions.
- A **local agent** runs in-process on the server host (no download needed).

---

## 9. Security (important — this executes nmap)

- **Only scan authorised targets.** Surface a clear warning in the rescan modal.
- **Validate flags server-side.** Disallow output-file redirection and shell
  metacharacters; build the argv as a list (never `shell=True`). Whitelist-ish:
  block `-oN/-oX/-oG/-oA` (server forces `-oX -`), block `--script` args that
  read arbitrary files unless explicitly allowed, cap `--min-rate`, etc.
- **Token auth** on `/ws/agent`; rotate/revoke tokens per agent.
- **Rate/limits:** one running job per agent by default; timeouts; max output
  buffer size.
- Agents run nmap with the privileges of whoever launched them — document that
  SYN scans need root/cap_net_raw on the agent host.

---

## 10. Suggested implementation order

1. `jobs`/`agents` tables + `db` helpers.
2. Local in-process runner first (thread + `subprocess` streaming) — proves
   rescan + stop + live output without any networking.
3. Rescan modal + live output panel + Stop, wired to the local runner.
4. `/ws/agent` protocol + in-memory agent registry.
5. Agent script generator + `/api/agents/*`.
6. Remote end-to-end: enroll → download agent → run on another box → rescan
   through it → result appears as a new scan.
7. Flag validation hardening + docs.

---

## 11. Integration notes / gotchas

- Results already fit Phase 1: they become scans via `db.insert_scan`, so the
  table/detail/notes/checkmark/merge/export features all work on rescan output
  for free.
- `parsers.parse_xml` accepts a `bytes|str` blob — feed it the agent's `-oX -`
  stdout directly.
- Reuse the existing `websockets` dependency (already installed via
  `uvicorn[standard]`).
- Keep the local-agent path always available so the tool stays useful on one
  machine.
