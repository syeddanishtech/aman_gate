#!/usr/bin/env bash
# Start AMAN Gate on :8000 (real FastAPI backend serving the built UI). Runs as the devcontainer
# postAttachCommand. It launches uvicorn in the background and waits for health, so attaching finishes
# and Codespaces auto-forwards the port (which opens the app in the browser).
set -euo pipefail
cd "$(dirname "$0")/../backend"

# Already up (e.g. re-attach)? Do nothing.
if curl -sf http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
  echo "AMAN Gate already running on :8000"
  exit 0
fi

export AMAN_ENV=demo
echo "[start] launching AMAN Gate on 0.0.0.0:8000 ..."
nohup python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/aman_gate.log 2>&1 &

# Wait up to ~40s for the server to answer, so the forwarded port is detected.
for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    echo "AMAN Gate is up on :8000 — open the forwarded port (the demo login is on screen)."
    exit 0
  fi
  sleep 1
done

echo "AMAN Gate did not answer in time; see /tmp/aman_gate.log" >&2
exit 0  # don't fail the attach; the user can run this script again
