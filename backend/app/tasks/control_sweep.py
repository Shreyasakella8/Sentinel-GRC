"""
SENTINEL-GRC — Control Sweep Tasks
Uses global SessionLocalSync — no per-task engine creation.
Saves chain_hash into every EvidenceEntry row.
"""

import time
import json
from datetime import datetime
from typing import Optional
import structlog

from app.tasks.celery_app import celery_app
from app.core.config import settings

logger = structlog.get_logger()

CONTROL_RUNNERS = {
    "AC-001": ("app.control_runners.access_control", "check_password_policy"),
    "AC-002": ("app.control_runners.access_control", "check_privileged_accounts"),
    "AC-003": ("app.control_runners.access_control", "check_mfa"),
    "NS-001": ("app.control_runners.network",         "check_exposed_ports"),
    "NS-002": ("app.control_runners.network",         "check_tls_certificates"),
    "NS-003": ("app.control_runners.network",         "check_firewall_rules"),
    "DP-001": ("app.control_runners.monitoring",      "check_disk_encryption"),
    "DP-002": ("app.control_runners.monitoring",      "check_backups"),
    "LM-001": ("app.control_runners.monitoring",      "check_log_retention"),
    "LM-002": ("app.control_runners.monitoring",      "check_alerting"),
    "VM-001": ("app.control_runners.vuln",            "check_patch_status"),
    "VM-002": ("app.control_runners.vuln",            "check_endpoint_protection"),
}

CRITICAL_CONTROLS = {"NS-001", "AC-002", "AC-003", "DP-001"}


def _run_single_control(control_id: str) -> Optional[dict]:
    if control_id not in CONTROL_RUNNERS:
        logger.error("Unknown control ID", control_id=control_id)
        return None

    module_path, func_name = CONTROL_RUNNERS[control_id]
    t0 = time.time()
    try:
        module      = __import__(module_path, fromlist=[func_name])
        runner_func = getattr(module, func_name)
        result      = runner_func()
        duration_ms = int((time.time() - t0) * 1000)
        logger.info("Control runner complete", control_id=control_id,
                    passed=result.passed, duration_ms=duration_ms)
        _store_result(result, duration_ms)
        return result.to_dict()
    except Exception as e:
        logger.error("Control runner failed", control_id=control_id, error=str(e))
        return None


def _store_result(result, duration_ms: int):
    """
    Persist ControlResult + EvidenceEntry.
    Uses global SessionLocalSync — no engine created here.
    chain_hash is computed and stored.
    """
    from app.db.database import SessionLocalSync
    from app.models.control  import ControlResult
    from app.models.evidence  import EvidenceEntry
    from app.models.risk      import Risk
    from app.services.evidence_vault import evidence_vault
    from app.services.risk_engine    import risk_engine
    from sqlalchemy import select, desc, func

    session = SessionLocalSync()
    try:
        # Store blob in MinIO
        evidence_data = evidence_vault.store_evidence(
            control_id    = result.control_id,
            evidence_type = "control_result",
            raw_data      = result.raw_output,
            metadata      = {
                "control_name": result.control_name,
                "passed":       result.passed,
                "status":       result.status,
                "finding":      result.finding,
            },
        )

        # Get previous entry for chain link
        prev_entry = session.execute(
            select(EvidenceEntry)
            .where(EvidenceEntry.control_id == result.control_id)
            .order_by(desc(EvidenceEntry.collected_at))
            .limit(1)
        ).scalar_one_or_none()

        prev_content_hash = prev_entry.content_hash if prev_entry else None

        # Compute composite chain hash — and SAVE it
        chain_hash = evidence_vault.compute_chain_hash(
            evidence_data["content_hash"], prev_content_hash
        )

        now       = datetime.utcnow()
        entry_ref = f"EVD-{now.strftime('%Y%m%d%H%M%S')}-{result.control_id}"

        db_evidence = EvidenceEntry(
            entry_ref           = entry_ref,
            control_id          = result.control_id,
            evidence_type       = "control_result",
            summary             = result.finding,
            raw_data_key        = evidence_data["object_key"],
            content_hash        = evidence_data["content_hash"],
            hmac_signature      = evidence_data["hmac_signature"],
            previous_entry_hash = prev_content_hash,
            chain_hash          = chain_hash,          # ← saved to DB
            chain_valid         = True,
            frameworks_covered  = ",".join(result.frameworks_failed or []),
            collected_by        = "automated_runner",
            collected_at        = now,
        )
        session.add(db_evidence)

        db_result = ControlResult(
            control_id           = result.control_id,
            control_name         = result.control_name,
            status               = result.status,
            passed               = result.passed,
            finding              = result.finding,
            raw_output           = json.dumps(result.raw_output),
            evidence_hash        = evidence_data["content_hash"],
            evidence_key         = evidence_data["object_key"],
            risk_contribution_gbp = result.risk_contribution_gbp,
            executed_at          = now,
            execution_duration_ms = duration_ms,
            runner_version       = "1.0.2",
        )
        session.add(db_result)

        if not result.passed and result.risk_contribution_gbp > 0:
            _auto_create_risk(session, result, risk_engine)

        session.commit()
        logger.info("Stored result + evidence", control_id=result.control_id,
                    entry_ref=entry_ref, chain_hash=chain_hash[:12])

    except Exception as e:
        session.rollback()
        logger.error("Failed to store control result", error=str(e))
    finally:
        session.close()


def _auto_create_risk(session, result, risk_engine):
    from app.models.risk import Risk
    from sqlalchemy import select, func

    existing = session.execute(
        select(Risk)
        .where(Risk.source_control_id == result.control_id)
        .where(Risk.status == "open")
    ).scalar_one_or_none()

    if existing:
        existing.updated_at = datetime.utcnow()
        return

    tef  = 5.0 if result.risk_contribution_gbp > 500_000 else 3.0 if result.risk_contribution_gbp > 100_000 else 2.0
    vuln = 0.6 if result.risk_contribution_gbp > 500_000 else 0.5 if result.risk_contribution_gbp > 100_000 else 0.4

    calc = risk_engine.calculate_risk(
        asset_value_gbp              = result.risk_contribution_gbp * 2,
        threat_event_frequency       = tef,
        vulnerability_probability    = vuln,
        primary_loss_magnitude_gbp   = result.risk_contribution_gbp,
        secondary_loss_magnitude_gbp = result.risk_contribution_gbp * 0.5,
        regulatory_fine_exposure_gbp = 17_500_000 if "GDPR" in str(result.frameworks_failed) else 0,
    )

    count    = session.execute(select(func.count(Risk.id))).scalar()
    risk_ref = f"RISK-{str(count + 1).zfill(4)}"

    session.add(Risk(
        risk_ref                       = risk_ref,
        title                          = f"Control Failure: {result.control_name}",
        description                    = result.finding,
        category                       = "cyber",
        source                         = "control_runner",
        source_control_id              = result.control_id,
        frameworks_impacted            = result.frameworks_failed,
        asset_type                     = "server",
        data_sensitivity               = "internal",
        threat_event_frequency         = tef,
        vulnerability_probability      = vuln,
        primary_loss_magnitude_gbp     = result.risk_contribution_gbp,
        secondary_loss_magnitude_gbp   = result.risk_contribution_gbp * 0.5,
        annualised_loss_expectancy_gbp = calc["ale_mean_gbp"],
        ale_10th_percentile_gbp        = calc["ale_10th_percentile_gbp"],
        ale_90th_percentile_gbp        = calc["ale_90th_percentile_gbp"],
        exploitation_probability_12m   = calc["exploitation_probability_12m"],
        last_monte_carlo_run           = datetime.utcnow(),
        severity                       = calc["severity"],
        status                         = "open",
    ))


@celery_app.task(name="app.tasks.control_sweep.run_full_sweep", bind=True)
def run_full_sweep(self):
    logger.info("Full control sweep starting", task_id=self.request.id)
    results = {}
    for cid in CONTROL_RUNNERS:
        try:
            r = _run_single_control(cid)
            results[cid] = {"status": r["status"] if r else "error",
                            "passed": r["passed"] if r else False}
        except Exception as e:
            results[cid] = {"status": "error", "error": str(e)}

    passed = sum(1 for r in results.values() if r.get("passed"))
    total  = len(results)
    logger.info("Full sweep complete", passed=passed, failed=total - passed)
    return {"passed": passed, "failed": total - passed, "total": total, "results": results}


@celery_app.task(name="app.tasks.control_sweep.run_critical_controls", bind=True)
def run_critical_controls(self):
    return {cid: _run_single_control(cid) for cid in CRITICAL_CONTROLS if cid in CONTROL_RUNNERS}


@celery_app.task(name="app.tasks.control_sweep.run_single_control_task")
def run_single_control_task(control_id: str):
    return _run_single_control(control_id)
