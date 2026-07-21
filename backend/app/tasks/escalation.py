"""
SENTINEL-GRC — Escalation Engine
Global SessionLocalSync. 72h SLA, £500K board threshold.
"""

from datetime import datetime, timedelta
import structlog
from app.tasks.celery_app import celery_app
from app.services.slack_notifier import send_risk_alert_sync
logger = structlog.get_logger()

ESCALATION_SLA_HOURS = 72
BOARD_THRESHOLD_GBP  = 500_000


@celery_app.task(name="app.tasks.escalation.check_and_escalate", bind=True)
def check_and_escalate(self):
    from app.db.database import SessionLocalSync
    from app.models.risk import Risk
    from app.models.governance import AuditFinding
    from app.models.threat import AuditLog
    from sqlalchemy import select

    session  = SessionLocalSync()
    esc_count = board_count = sla_count = 0

    try:
        cutoff = datetime.utcnow() - timedelta(hours=ESCALATION_SLA_HOURS)

        # Overdue critical/high risks
        overdue = session.execute(
            select(Risk).where(
                Risk.status.in_(["open"]),
                Risk.severity.in_(["critical", "high"]),
                Risk.created_at < cutoff,
                Risk.escalated == False,
            )
        ).scalars().all()

        for risk in overdue:
            risk.escalated       = True
            risk.escalated_at    = datetime.utcnow()
            risk.escalation_level = (risk.escalation_level or 0) + 1
            session.add(AuditLog(
                user_email   = "system@sentinel.local",
                user_role    = "system",
                action       = "RISK_AUTO_ESCALATED",
                resource_type = "risk",
                resource_id  = str(risk.id),
                details      = {
                    "risk_ref":        risk.risk_ref,
                    "severity":        risk.severity,
                    "ale_gbp":         risk.annualised_loss_expectancy_gbp,
                    "escalation_level": risk.escalation_level,
                    "reason": f"No treatment within {ESCALATION_SLA_HOURS}h",
                },
            ))
            # ─── Slack alert for escalated risk ─────────────────────────────────────────
            send_risk_alert_sync(
                event_type="risk_escalated",
                risk_ref=risk.risk_ref,
                title=risk.title,
                severity=risk.severity,
                ale_gbp=risk.annualised_loss_expectancy_gbp or 0,
                detail=(
                    f"Risk has been open for over {ESCALATION_SLA_HOURS}h without treatment. "
                    f"Escalation level: {risk.escalation_level}."
                ),
            )
            esc_count += 1

        # Board threshold
        board_needed = session.execute(
            select(Risk).where(
                Risk.status.in_(["open", "under_treatment"]),
                Risk.annualised_loss_expectancy_gbp >= BOARD_THRESHOLD_GBP,
                Risk.board_approved == False,
                Risk.board_threshold_exceeded == False,
            )
        ).scalars().all()

        for risk in board_needed:
            risk.board_threshold_exceeded = True
            session.add(AuditLog(
                user_email   = "system@sentinel.local",
                user_role    = "system",
                action       = "BOARD_APPROVAL_REQUIRED",
                resource_type = "risk",
                resource_id  = str(risk.id),
                details      = {
                    "risk_ref":      risk.risk_ref,
                    "ale_gbp":       risk.annualised_loss_expectancy_gbp,
                    "threshold_gbp": BOARD_THRESHOLD_GBP,
                },
            ))
            # ─── Slack alert for board threshold breach ────────────────────────────────────
            send_risk_alert_sync(
                event_type="board_threshold",
                risk_ref=risk.risk_ref,
                title=risk.title,
                severity=risk.severity or "high",
                ale_gbp=risk.annualised_loss_expectancy_gbp or 0,
                detail=(
                    f"ALE £{risk.annualised_loss_expectancy_gbp:,.0f} exceeds board approval "
                    f"threshold of £{BOARD_THRESHOLD_GBP:,}. Board sign-off required."
                ),
            )
            board_count += 1

        # Audit finding SLA
        sla_breached = session.execute(
            select(AuditFinding).where(
                AuditFinding.status.in_(["open", "in_progress"]),
                AuditFinding.remediation_due < datetime.utcnow(),
                AuditFinding.sla_breached == False,
            )
        ).scalars().all()

        for f in sla_breached:
            f.sla_breached = True
            sla_count += 1

        session.commit()
        logger.info("Escalation done", escalated=esc_count, board=board_count, sla=sla_count)
        return {"escalated": esc_count, "board_flagged": board_count, "sla_breached": sla_count}
    except Exception as e:
        session.rollback()
        logger.error("Escalation check failed", error=str(e))
        return {"error": str(e)}
    finally:
        session.close()
