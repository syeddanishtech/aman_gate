#!/usr/bin/env bash
# One-time Codespace setup: install the pinned backend deps, train the advisory model, build the frontend.
# Runs as the devcontainer postCreateCommand. The container's Python is 3.12 and Node is provided by the
# node feature, so we install into the container directly (it is disposable).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[setup] backend dependencies (pinned)"
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt

echo "[setup] train the advisory injection classifier (offline, synthetic)"
( cd backend && python -m scripts.train_model )

echo "[setup] build the frontend (served by the API at /)"
( cd frontend && npm ci && npm run build )

echo "[setup] done — the app will auto-start on port 8000 when the Codespace attaches."
