"""
SENTINEL-GRC — Risk Recalculation Task

Improvements applied:
  1. Session safety: uses get_db_session() context manager instead of manual
     try/except/finally. Guarantees session.close() on all paths including
     mid-loop exceptions during bulk processing of open risks.
  2. None-check (not truthiness) for zero-valued FAIR params (unchanged).
"""

from datetime import datetime
import structlog
from app.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(name="app.tasks.risk_recalculation.recalculate_all_risks", bind=True)
def recalculate_all_risks(self):
    from app.db.database import get_db_session
    from app.models.risk import Risk, RiskScore
    from app.services.risk_engine import risk_engine
    from sqlalchemy import select

    logger.info("Risk recalculation starting")

    with get_db_session() as session:
        try:
            open_risks = session.execute(
                select(Risk).where(Risk.status.in_(["open", "under_treatment"]))
            ).scalars().all()

            updated = 0
            for risk in open_risks:
                # None-check — 0.0 is valid, must not be skipped
                if any(v is None for v in [
                    risk.threat_event_frequency,
                    risk.vulnerability_probability,
                    risk.primary_loss_magnitude_gbp,
                ]):
                    continue

                try:
                    calc = risk_engine.calculate_risk(
                        asset_value_gbp              = risk.asset_value_gbp or 500_000,
                        threat_event_frequency       = risk.threat_event_frequency,
                        vulnerability_probability    = risk.vulnerability_probability,
                        primary_loss_magnitude_gbp   = risk.primary_loss_magnitude_gbp,
                        secondary_loss_magnitude_gbp = risk.secondary_loss_magnitude_gbp or 0,
                        regulatory_fine_exposure_gbp = risk.regulatory_fine_exposure_gbp or 0,
                        data_sensitivity             = risk.data_sensitivity or "internal",
                        asset_type                   = risk.asset_type or "server",
                    )

                    old_ale = risk.annualised_loss_expectancy_gbp
                    risk.annualised_loss_expectancy_gbp = calc["ale_mean_gbp"]
                    risk.ale_10th_percentile_gbp        = calc["ale_10th_percentile_gbp"]
                    risk.ale_90th_percentile_gbp        = calc["ale_90th_percentile_gbp"]
                    risk.exploitation_probability_12m   = calc["exploitation_probability_12m"]
                    risk.severity                       = calc["severity"]
                    risk.last_monte_carlo_run           = datetime.utcnow()

                    session.add(RiskScore(
                        risk_id     = risk.id,
                        ale_gbp     = calc["ale_mean_gbp"],
                        severity    = calc["severity"],
                        recorded_at = datetime.utcnow(),
                        trigger     = "scheduled_recalc",
                    ))

                    if old_ale and abs(calc["ale_mean_gbp"] - old_ale) > 50_000:
                        logger.info(
                            "ALE delta > £50K",
                            risk_ref=risk.risk_ref,
                            old=round(old_ale),
                            new=round(calc["ale_mean_gbp"]),
                        )
                    updated += 1
                except Exception as e:
                    logger.error("Recalc failed for risk", risk_ref=risk.risk_ref, error=str(e))

            session.commit()
            logger.info("Recalc complete", updated=updated, total=len(open_risks))
            return {"updated": updated, "total": len(open_risks)}

        except Exception as e:
            session.rollback()
            logger.error("Recalculation sweep failed", error=str(e))
            return {"error": str(e)}
