#!/usr/bin/env bash
# Launch the nmap-viewer web app.
#
#   ./run.sh            # http://127.0.0.1:8770
#   HOST=0.0.0.0 PORT=9000 ./run.sh
set -euo pipefail

cd "$(dirname "$0")"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8770}"

# Create the venv on first run.
if [ ! -d venv ]; then
    echo "[*] Creating virtual environment…"
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q
    ./venv/bin/pip install -q -r requirements.txt
fi

echo "[*] nmap-viewer → http://${HOST}:${PORT}"
# --reload picks up backend code changes automatically (no manual restart).
# Set NO_RELOAD=1 to disable (e.g. for a stable/hosted run).
if [ "${NO_RELOAD:-0}" = "1" ]; then
    exec ./venv/bin/uvicorn backend.app:app --host "$HOST" --port "$PORT"
else
    exec ./venv/bin/uvicorn backend.app:app --host "$HOST" --port "$PORT" \
        --reload --reload-dir backend --reload-dir frontend
fi
