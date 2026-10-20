# AMAN Gate — start the API (serves the built frontend at http://127.0.0.1:8000/).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location "$root/backend"
$py = "$root/backend/.venv/Scripts/python.exe"
if (-not (Test-Path $py)) { Write-Error "Backend venv missing. Run ./scripts/setup.ps1 first."; exit 1 }
Write-Host "AMAN Gate running at http://127.0.0.1:8000/  (Ctrl+C to stop)" -ForegroundColor Green
& $py -m uvicorn app.main:app --host 127.0.0.1 --port 8000
