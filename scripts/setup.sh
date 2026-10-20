#!/usr/bin/env bash
# AMAN Gate — one-command setup for Linux/macOS.
# Usage:  ./scripts/setup.sh
# Requires: Python 3.12 (or uv), Node.js 18+.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "== AMAN Gate setup =="

cd "$ROOT/backend"
if command -v uv >/dev/null 2>&1; then
  echo "[backend] creating venv with uv (pinned from uv.lock)..."
  uv sync --python 3.12
  PY="$ROOT/backend/.venv/bin/python"
else
  echo "[backend] uv not found; using python3 -m venv + pip..."
  python3 -m venv .venv
  PY="$ROOT/backend/.venv/bin/python"
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r requirements.txt -r requirements-dev.txt
fi

echo "[backend] training advisory injection classifier..."
"$PY" -m scripts.train_model

cd "$ROOT/frontend"
echo "[frontend] installing dependencies..."
npm install --no-audit --no-fund
echo "[frontend] building static assets..."
npm run build

cd "$ROOT"
echo ""
echo "== Setup complete =="
echo "Start the app with:  ./scripts/run.sh"
echo "Then open http://127.0.0.1:8000/"
