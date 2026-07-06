"""
SENTINEL-GRC — Celery Task Engine
Scheduled control runners and async processing.
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
    worker_prefetch_multiplier=1,
    # Queue routing
    task_routes={
        "app.tasks.control_sweep.*": {"queue": "controls"},
        "app.tasks.report_generation.*": {"queue": "reports"},
        "app.tasks.threat_intelligence.*": {"queue": "threats"},
        "app.tasks.risk_recalculation.*": {"queue": "controls"},
        "app.tasks.escalation.*": {"queue": "controls"},
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
        "schedule": 3600,  # Every hour
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
        "schedule": crontab(hour=6, minute=0),  # 6am UTC daily
        "options": {"queue": "threats"},
    },
    # Escalation checker every 30 minutes
    "escalation-check": {
        "task": "app.tasks.escalation.check_and_escalate",
        "schedule": 1800,
        "options": {"queue": "controls"},
    },
    # Risk recalculation daily
    "daily-risk-recalc": {
        "task": "app.tasks.risk_recalculation.recalculate_all_risks",
        "schedule": crontab(hour=2, minute=0),  # 2am UTC daily
        "options": {"queue": "controls"},
    },
}
