#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
PY="$ROOT/backend/.venv/bin/python"
[ -x "$PY" ] || { echo "Backend venv missing. Run ./scripts/setup.sh first."; exit 1; }
echo "AMAN Gate running at http://127.0.0.1:8000/  (Ctrl+C to stop)"
exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
