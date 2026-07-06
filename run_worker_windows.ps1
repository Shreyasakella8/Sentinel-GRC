# SENTINEL-GRC - Native Windows Celery Worker
# This script runs the Celery worker locally on your Windows machine
# allowing it to execute Windows-specific compliance checks (e.g., Get-HotFix, manage-bde)

Write-Host "Stopping Docker celery worker to prevent conflicts..." -ForegroundColor Cyan
docker stop sentinel_celery

Write-Host "Setting up Python virtual environment..." -ForegroundColor Cyan
cd backend
if (-Not (Test-Path "venv")) {
    python -m venv venv
}

# Activate venv
.\venv\Scripts\Activate.ps1

Write-Host "Installing requirements..." -ForegroundColor Cyan
pip install -r requirements.txt

Write-Host "Setting Environment Variables for localhost access..." -ForegroundColor Cyan
$env:DATABASE_URL="postgresql+asyncpg://sentinel:sentinel_secret@localhost:5432/sentinel_grc"
$env:SYNC_DATABASE_URL="postgresql://sentinel:sentinel_secret@localhost:5432/sentinel_grc"
$env:REDIS_URL="redis://localhost:6379/0"
$env:CELERY_BROKER_URL="redis://localhost:6379/0"
$env:CELERY_RESULT_BACKEND="redis://localhost:6379/0"
$env:MINIO_ENDPOINT="localhost:9000"
$env:MINIO_ACCESS_KEY="sentinel_minio"
$env:MINIO_SECRET_KEY="sentinel_minio_secret"
$env:MINIO_BUCKET="evidence-vault"
$env:SECRET_KEY="CHANGE_THIS_IN_PRODUCTION_super_secret_jwt_key_sentinel_grc_2024"

Write-Host "Starting Native Windows Celery Worker..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow

# Run celery with solo pool (prefork doesn't work well on Windows)
celery -A app.tasks.celery_app worker --loglevel=info -Q controls,reports,threats --pool=solo
