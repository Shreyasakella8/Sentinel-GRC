# SENTINEL-GRC — Stop Script (Windows)
Write-Host "Stopping SENTINEL-GRC..." -ForegroundColor Cyan
try {
    docker compose down
} catch {
    docker-compose down
}
Write-Host "All services stopped." -ForegroundColor Green
