"""
SENTINEL-GRC — Application Configuration
All settings loaded from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # ─── App ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "SENTINEL-GRC"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # ─── Security ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = "change_this_in_production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24h

    # ─── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str
    SYNC_DATABASE_URL: str

    # ─── Database Pool Tuning ─────────────────────────────────────────────────
    # Sizing formula for async pool (FastAPI):
    #   DB_POOL_SIZE = (num_cpu_cores × 2) + effective_spindle_count
    #   e.g. 4-core server → (4 × 2) + 0 = 8; we default to 20 for headroom
    # Sizing formula for sync pool (Celery):
    #   SYNC_DB_POOL_SIZE = min(celery_concurrency, 10)
    # Monitor: SELECT count(*) FROM pg_stat_activity;
    # Alert if count > DB_POOL_SIZE + DB_MAX_OVERFLOW - 2
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    SYNC_DB_POOL_SIZE: int = 10
    SYNC_DB_MAX_OVERFLOW: int = 10

    # ─── Redis / Celery ───────────────────────────────────────────────────────
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"

    # ─── MinIO ────────────────────────────────────────────────────────────────
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "sentinel_minio"
    MINIO_SECRET_KEY: str = "sentinel_minio_secret"
    MINIO_BUCKET: str = "evidence-vault"
    MINIO_SECURE: bool = False

    # ─── First Superuser ──────────────────────────────────────────────────────
    FIRST_SUPERUSER_EMAIL: str = "admin@sentinel.local"
    FIRST_SUPERUSER_PASSWORD: str = "SentinelAdmin@2024"
    FIRST_SUPERUSER_NAME: str = "System Administrator"

    # ─── Threat Intelligence ──────────────────────────────────────────────────
    NVD_API_KEY: Optional[str] = None
    MITRE_ATTACK_API: str = "https://attack.mitre.org/"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # ─── Control Runner ───────────────────────────────────────────────────────
    CONTROL_SWEEP_INTERVAL: int = 21600
    RISK_ALERT_THRESHOLD_GBP: int = 50000

    # ─── Reports ──────────────────────────────────────────────────────────────
    ORG_NAME: str = "Your Organisation Ltd"
    ORG_LOGO_PATH: str = "/app/static/logo.png"
    REPORT_OUTPUT_DIR: str = "/app/reports"

    # ─── Evidence HMAC ────────────────────────────────────────────────────────
    EVIDENCE_HMAC_KEY: str = "change_this_evidence_signing_key_32_chars_minimum"

    # ─── Slack Alerting ───────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_ALERT_CHANNEL: Optional[str] = "#security-alerts"

    # ─── Feature Flags (safe rollback without redeploy) ───────────────────────
    # Set ENABLE_PAGINATION=false to fall back to old unbounded list behaviour
    ENABLE_PAGINATION: bool = True
    # Set ENABLE_EVIDENCE_DEDUP=false to disable content-hash deduplication
    ENABLE_EVIDENCE_DEDUP: bool = True
    # Set ENABLE_AUDIT_MIDDLEWARE=false to disable async audit capture
    ENABLE_AUDIT_MIDDLEWARE: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
