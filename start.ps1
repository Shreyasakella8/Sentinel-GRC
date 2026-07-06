# ============================================================
# SENTINEL-GRC — Windows PowerShell Startup Script
# Run from inside the sentinel-grc folder:
#   cd sentinel-grc
#   .\start.ps1
# ============================================================

$ErrorActionPreference = "Stop"

$RED    = "`e[31m"
$GREEN  = "`e[32m"
$CYAN   = "`e[36m"
$YELLOW = "`e[33m"
$WHITE  = "`e[97m"
$RESET  = "`e[0m"

Write-Host ""
Write-Host "$RED  ____  _____ _   _ _____ ___ _   _ _____ _     $RESET"
Write-Host "$RED / ___|| ____| \ | |_   _|_ _| \ | | ____| |    $RESET"
Write-Host "$RED \___ \|  _| |  \| | | |  | ||  \| |  _| | |    $RESET"
Write-Host "$RED  ___) | |___| |\  | | |  | || |\  | |___| |___ $RESET"
Write-Host "$RED |____/|_____|_| \_| |_| |___|_| \_|_____|_____|$RESET"
Write-Host ""
Write-Host "$CYAN  Enterprise Continuous Controls Monitoring and Risk Intelligence Platform$RESET"
Write-Host "$WHITE  Version 1.0.0 — All modules local — Zero cloud dependency$RESET"
Write-Host ""
Write-Host "------------------------------------------------------------"

# ── Check Docker is installed and running ──────────────────────────────────
Write-Host "`n$CYAN> Checking prerequisites...$RESET"

try {
    $dockerVersion = docker --version 2>&1
    Write-Host "$GREEN  [OK] Docker found: $dockerVersion$RESET"
} catch {
    Write-Host "$RED  [ERROR] Docker not found.$RESET"
    Write-Host "    Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    Write-Host "    Make sure 'Use WSL 2 based engine' is enabled in Docker Desktop settings."
    Read-Host "Press Enter to exit"
    exit 1
}

# Check Docker daemon is actually running
try {
    docker info 2>&1 | Out-Null
    Write-Host "$GREEN  [OK] Docker daemon is running$RESET"
} catch {
    Write-Host "$RED  [ERROR] Docker daemon is not running.$RESET"
    Write-Host "    Please start Docker Desktop and wait for it to fully load, then re-run this script."
    Read-Host "Press Enter to exit"
    exit 1
}

# ── Copy .env if missing ───────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Write-Host "$YELLOW  [WARN] No .env file found - copying from .env.example$RESET"
    Copy-Item ".env.example" ".env"
    Write-Host "$GREEN  [OK] .env created$RESET"
} else {
    Write-Host "$GREEN  [OK] .env found$RESET"
}

# ── Build and start all containers ────────────────────────────────────────
Write-Host "`n$CYAN> Building and starting SENTINEL-GRC (this takes 2-4 minutes on first run)...$RESET`n"

try {
    docker compose up --build -d
} catch {
    # Fallback for older Docker Compose V1
    docker-compose up --build -d
}

Write-Host "`n$CYAN> Waiting for services to become healthy...$RESET"

# Wait for backend health check
$maxAttempts = 40
$attempt = 0
$backendReady = $false

while ($attempt -lt $maxAttempts -and -not $backendReady) {
    Start-Sleep -Seconds 3
    $attempt++
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $backendReady = $true
        }
    } catch {
        # Still starting
    }
    Write-Host "  Attempt $attempt/$maxAttempts - waiting for backend..." -NoNewline
    Write-Host "`r" -NoNewline
}

Write-Host ""

if ($backendReady) {
    Write-Host "$GREEN  [OK] Backend is healthy$RESET"
} else {
    Write-Host "$YELLOW  [WARN] Backend may still be initialising. Check logs: docker compose logs backend$RESET"
}

# ── Print access info ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "------------------------------------------------------------"
Write-Host "$GREEN  * SENTINEL-GRC IS RUNNING *$RESET"
Write-Host ""
Write-Host "  $WHITE Frontend Dashboard:$RESET    $CYAN http://localhost:3000 $RESET"
Write-Host "  $WHITE Backend API:$RESET            $CYAN http://localhost:8000 $RESET"
Write-Host "  $WHITE API Docs (Swagger):$RESET     $CYAN http://localhost:8000/api/docs $RESET"
Write-Host "  $WHITE MinIO Evidence Store:$RESET   $CYAN http://localhost:9001 $RESET"
Write-Host ""
Write-Host "  $WHITE Default Login:$RESET"
Write-Host "  $CYAN  Email:$RESET    admin@sentinel.local"
Write-Host "  $CYAN  Password:$RESET SentinelAdmin@2024"
Write-Host ""
Write-Host "  $WHITE MinIO Console (http://localhost:9001):$RESET"
Write-Host "  $CYAN  User:$RESET     sentinel_minio"
Write-Host "  $CYAN  Password:$RESET sentinel_minio_secret"
Write-Host ""
Write-Host "------------------------------------------------------------"
Write-Host ""
Write-Host "  $YELLOW Quick Start:$RESET"
Write-Host "  1. Open http://localhost:3000 and log in"
Write-Host "  2. Go to $WHITE Controls$RESET -> click $WHITE 'Run Full Sweep Now'$RESET"
Write-Host "  3. Go to $WHITE Threats$RESET -> click $WHITE 'Refresh All Feeds'$RESET"
Write-Host "  4. Go to $WHITE Reports$RESET -> generate Board / Auditor / Technical PDFs"
Write-Host ""
Write-Host "  $YELLOW Useful Commands (run in this folder):$RESET"
Write-Host "  $CYAN  .\stop.ps1$RESET                  Stop all services"
# Using single quotes for logs commands to prevent variables/expressions warnings
Write-Host "  $CYAN  docker compose logs -f$RESET      Stream all logs"
Write-Host "  $CYAN  docker compose logs backend$RESET Backend logs only"
Write-Host "  $CYAN  docker compose ps$RESET           Check container status"
Write-Host ""

# Open browser automatically
Write-Host "$CYAN> Opening dashboard in your browser...$RESET"
Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"
