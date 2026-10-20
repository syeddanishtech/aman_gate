# AMAN Gate — Offline / Air-gapped Packaging

The **demo itself runs fully offline** (no sockets; `tests/test_no_network.py` enforces this). Internet is
only needed **once, during setup**, to download pinned Python and Node packages. To install on an
air-gapped machine, pre-stage those dependencies on a connected machine of the **same OS/arch**.

## Backend (Python, pinned)

Dependencies are pinned in `backend/uv.lock` (for `uv`) and `backend/requirements.txt` /
`requirements-dev.txt` (for `pip`).

On a connected machine (same OS + CPU arch as the target):
```bash
cd backend
mkdir wheelhouse
python -m pip download -r requirements.txt -r requirements-dev.txt -d wheelhouse
```
Copy `wheelhouse/` to the air-gapped machine, then:
```bash
cd backend
python -m venv .venv
.venv/bin/python -m pip install --no-index --find-links wheelhouse -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m scripts.train_model     # trains locally; no network
```
(With `uv`: `uv sync --python 3.12` resolves entirely from `uv.lock`; pre-seed the uv cache with
`uv cache` on the connected machine if the target has no package index.)

## Frontend (Node, pinned)

`frontend/package-lock.json` pins the tree. On a connected machine:
```bash
cd frontend
npm ci            # produces node_modules from the lockfile
npm run build     # produces dist/
```
Either copy `frontend/node_modules/` to the target before `npm run build`, or copy the already-built
`frontend/dist/` (the FastAPI app serves it at `/`, so the target then needs only the Python venv).

### Fonts
`index.css` imports Inter/JetBrains Mono from Google Fonts for nicety. Offline, the browser falls back to
system fonts (Segoe UI / Consolas) — the UI is fully functional without network access. To fully localise,
self-host the font files under `frontend/src/` and replace the `@import`.

## Minimal air-gapped run (no Node on target)
1. Build `frontend/dist/` on a connected machine.
2. Ship: `backend/` (with `wheelhouse/`), `frontend/dist/`, `backend/ml_artifacts/` (or train on target).
3. On target: create venv from `wheelhouse`, then `python -m uvicorn app.main:app --port 8000`.
4. Browse `http://127.0.0.1:8000/`.

## Docker (self-contained)
`docker compose up --build` produces an image that installs pinned deps, builds the UI and trains the model
at build time — after which the container needs no network. Build it on a connected machine, `docker save`
the image, and `docker load` on the target.
