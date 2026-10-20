# AMAN Gate — one-command setup for Windows (PowerShell).
# Usage:  ./scripts/setup.ps1
# Builds the backend venv (pinned deps), trains the advisory model, builds the frontend, and prints
# the run command. Requires: Python 3.12 (or uv), Node.js 18+.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "== AMAN Gate setup ==" -ForegroundColor Cyan

# --- Backend ---
Set-Location "$root/backend"
if (Get-Command uv -ErrorAction SilentlyContinue) {
  Write-Host "[backend] creating venv with uv (pinned, offline-capable from uv.lock)..."
  uv sync --python 3.12
  $py = "$root/backend/.venv/Scripts/python.exe"
} else {
  Write-Host "[backend] uv not found; using python -m venv + pip + requirements.txt..."
  python -m venv .venv
  $py = "$root/backend/.venv/Scripts/python.exe"
  & $py -m pip install --upgrade pip
  & $py -m pip install -r requirements.txt -r requirements-dev.txt
}

Write-Host "[backend] training advisory injection classifier..."
& $py -m scripts.train_model

# --- Frontend ---
Set-Location "$root/frontend"
Write-Host "[frontend] installing dependencies..."
npm install --no-audit --no-fund
Write-Host "[frontend] building static assets..."
npm run build

Set-Location $root
Write-Host ""
Write-Host "== Setup complete ==" -ForegroundColor Green
Write-Host "Start the app with:" -ForegroundColor Cyan
Write-Host "  ./scripts/run.ps1"
Write-Host "Then open http://127.0.0.1:8000/"
