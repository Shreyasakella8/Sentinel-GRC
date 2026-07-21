"""
SENTINEL-GRC — Celery Task Engine
Scheduled control runners and async processing.

Changes:
  - worker_prefetch_multiplier: 1 → 4
    Rationale: multiplier=1 means each worker fetches one task at a time from the
    broker, causing underutilisation during burst loads (12 control sweeps × workers).
    Multiplier=4 prefetches 4 tasks while processing 1, eliminating broker round-trip
    latency. task_acks_late=True is kept so tasks aren't lost if a worker crashes
    mid-execution (Celery won't ACK until the task finishes).
  - audit_log_task: new async task for writing AuditLog entries from HTTP middleware.
    Offloads DB write to a worker thread so audit capture adds zero latency to responses.
  - daily-backup beat schedule added.
"""

from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

# Create Celery app
celery_app = Celery(
    "sentinel_grc",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.control_sweep",
        "app.tasks.risk_recalculation",
        "app.tasks.threat_intelligence",
        "app.tasks.report_generation",
        "app.tasks.escalation",
        "app.tasks.celery_app",   # for audit_log_task defined below
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    # Changed from 1 → 4: prefetch 4 tasks per worker for burst throughput.
    # Keep task_acks_late=True to prevent data loss if worker crashes mid-task.
    worker_prefetch_multiplier=4,
    # Queue routing
    task_routes={
        "app.tasks.control_sweep.*":         {"queue": "controls"},
        "app.tasks.report_generation.*":     {"queue": "reports"},
        "app.tasks.threat_intelligence.*":   {"queue": "threats"},
        "app.tasks.risk_recalculation.*":    {"queue": "controls"},
        "app.tasks.escalation.*":            {"queue": "controls"},
        "app.tasks.celery_app.audit_log_task": {"queue": "default"},
    },
)

# ── Scheduled Tasks (Beat) ────────────────────────────────────────────────────
celery_app.conf.beat_schedule = {
    # Full control sweep every 6 hours
    "full-control-sweep": {
        "task": "app.tasks.control_sweep.run_full_sweep",
        "schedule": settings.CONTROL_SWEEP_INTERVAL,
        "options": {"queue": "controls"},
    },
    # High-frequency checks every hour
    "critical-control-sweep": {
        "task": "app.tasks.control_sweep.run_critical_controls",
        "schedule": 3600,
        "options": {"queue": "controls"},
    },
    # Threat intelligence refresh every 4 hours
    "threat-intelligence-refresh": {
        "task": "app.tasks.threat_intelligence.fetch_nvd_cves",
        "schedule": 14400,
        "options": {"queue": "threats"},
    },
    # CISA KEV refresh daily
    "cisa-kev-refresh": {
        "task": "app.tasks.threat_intelligence.fetch_cisa_kev",
        "schedule": crontab(hour=6, minute=0),
        "options": {"queue": "threats"},
    },
    # Escalation checker every 30 minutes
    "escalation-check": {
        "task": "app.tasks.escalation.check_and_escalate",
        "schedule": 1800,
        "options": {"queue": "controls"},
    },
    # Risk recalculation daily at 2 AM UTC
    "daily-risk-recalc": {
        "task": "app.tasks.risk_recalculation.recalculate_all_risks",
        "schedule": crontab(hour=2, minute=0),
        "options": {"queue": "controls"},
    },
    # Daily backup at 3 AM UTC (offset from recalc to avoid DB contention)
    "daily-backup": {
        "task": "app.tasks.celery_app.daily_backup",
        "schedule": crontab(hour=3, minute=0),
        "options": {"queue": "default"},
    },
}


# ── Async Audit Logging Task ──────────────────────────────────────────────────
@celery_app.task(name="app.tasks.celery_app.audit_log_task", ignore_result=True)
def audit_log_task(
    user_id: int | None,
    user_email: str | None,
    user_role: str | None,
    method: str,
    path: str,
    status_code: int,
    ip_address: str | None,
    user_agent: str | None,
    body_hash: str | None,
):
    """
    Write an AuditLog entry asynchronously from HTTP middleware.

    Called via .delay() so audit DB writes never block the HTTP response.
    Using body_hash (not full body) to avoid storing PII in audit logs.
    """
    import structlog as _structlog
    from app.db.database import get_db_session
    from app.models.threat import AuditLog

    _log = _structlog.get_logger()
    action = f"{method} {path} → {status_code}"

    with get_db_session() as session:
        try:
            session.add(AuditLog(
                user_id     = user_id,
                user_email  = user_email,
                user_role   = user_role,
                action      = action,
                resource_type = path.split("/")[3] if path.count("/") >= 3 else "unknown",
                details     = {"body_hash": body_hash, "status_code": status_code},
                ip_address  = ip_address,
                user_agent  = user_agent,
                success     = status_code < 400,
            ))
            session.commit()
        except Exception as e:
            session.rollback()
            _log.error("Audit log write failed", action=action, error=str(e))


# ── Daily Backup Task ─────────────────────────────────────────────────────────
@celery_app.task(name="app.tasks.celery_app.daily_backup", bind=True)
def daily_backup(self):
    """
    Placeholder backup task — integrate with your backup provider.

    Implementation options:
      - pg_dump | gzip → S3/GCS for PostgreSQL
      - mc mirror minio/evidence-vault → S3 for MinIO blobs
      - Encrypt with GPG before upload for compliance

    This task fires at 03:00 UTC daily via beat schedule.
    """
    import structlog as _structlog
    _log = _structlog.get_logger()
    _log.info(
        "Daily backup task triggered",
        hint="Implement pg_dump + MinIO mirror + S3 upload here",
    )
    return {"status": "backup_placeholder_triggered"}
