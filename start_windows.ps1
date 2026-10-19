# Start script for the DNS Tunneling Detection platform (Windows)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  DNS Tunneling Detection & Triage Console" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RootDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir  = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# ── Preflight ──────────────────────────────────────────────────────────────
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Python is not installed or not on PATH." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Node.js (npm) is not installed or not on PATH." -ForegroundColor Red
    exit 1
}

$envFile = Join-Path $BackendDir ".env"
if (-not (Test-Path $envFile)) {
    Write-Host "[!] backend\.env not found." -ForegroundColor Yellow
    Write-Host "    Copy backend\.env.example to backend\.env and set your database credentials." -ForegroundColor Yellow
    exit 1
}

# ── Dependencies ───────────────────────────────────────────────────────────
Write-Host "[*] Checking Python dependencies..." -ForegroundColor DarkCyan
python -c "import fastapi, psycopg2, scapy" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[*] Installing from requirements.txt..." -ForegroundColor DarkCyan
    python -m pip install -r (Join-Path $BackendDir "requirements.txt") --quiet
}

if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
    Write-Host "[*] Installing frontend dependencies (first run, this takes a while)..." -ForegroundColor DarkCyan
    Push-Location $FrontendDir
    npm install
    Pop-Location
}

# ── Schema ─────────────────────────────────────────────────────────────────
Write-Host "[*] Initializing and migrating database schema..." -ForegroundColor DarkCyan
Push-Location $BackendDir
python database.py
$schemaExit = $LASTEXITCODE
Pop-Location

if ($schemaExit -ne 0) {
    Write-Host "[!] Schema initialization failed. Check the database credentials in backend\.env." -ForegroundColor Red
    exit 1
}

# ── Services ───────────────────────────────────────────────────────────────
Write-Host "[*] Starting API on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
$api = Start-Process -FilePath "python" -ArgumentList "api.py" -WorkingDirectory $BackendDir -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 3

if ($api.HasExited) {
    Write-Host "[!] API failed to start. Run 'python api.py' in backend\ to see the error." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Starting dashboard on http://localhost:3000 ..." -ForegroundColor Cyan
Start-Process -FilePath "npm.cmd" -ArgumentList "start" -WorkingDirectory $FrontendDir -WindowStyle Hidden

Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"

Write-Host ""
Write-Host "[+] Services running." -ForegroundColor Green
Write-Host "    Dashboard : http://localhost:3000" -ForegroundColor Yellow
Write-Host "    API       : http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "    API docs  : http://127.0.0.1:8000/docs" -ForegroundColor Yellow
Write-Host ""
Write-Host "    API process id: $($api.Id)" -ForegroundColor DarkGray
Write-Host "    Stop it with:  Stop-Process -Id $($api.Id)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Press any key to close this window (services keep running)." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
