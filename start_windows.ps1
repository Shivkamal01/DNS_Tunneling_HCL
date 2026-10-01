# Start Script for DNS Tunneling HCL (Windows)

Write-Host "Starting DNS Tunneling SOC Platform..." -ForegroundColor Green

# 1. Check if python is installed
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "Python is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# 2. Check if node is installed
if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "Node.js (npm) is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# 3. Start Backend API (working directory = backend/ so relative imports work)
Write-Host "Starting Backend FastAPI Server on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Start-Process -FilePath "python" -ArgumentList "api.py" -WorkingDirectory $BackendDir -NoNewWindow

# 4. Start Frontend
Write-Host "Starting Frontend React App on http://localhost:3000 ..." -ForegroundColor Cyan
Start-Process -FilePath "npm.cmd" -ArgumentList "start" -WorkingDirectory $FrontendDir

Write-Host ""
Write-Host "Both services started!" -ForegroundColor Green
Write-Host "  Backend API:     http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "  SOC Dashboard:   http://localhost:3000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to exit this window (services will continue running)." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
