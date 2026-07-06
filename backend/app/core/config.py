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

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
