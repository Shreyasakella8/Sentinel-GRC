"""
SENTINEL-GRC — Control Sweep Tasks

Improvements applied:
  1. Session safety: _store_result() uses get_db_session() context manager.
     Previously session.close() in a finally block could be skipped on some
     exception types, leaking connections over long-running workers.
  2. Evidence deduplication: before uploading to MinIO, content_hash is checked
     against existing EvidenceEntry rows. If identical content was stored before
     (e.g. password policy passes every 6 hours for years), the existing blob
     is reused — no re-upload, no duplicate MinIO object, reduced storage growth.
     Algorithm:
       a. Compute content_hash from raw_data BEFORE MinIO upload
       b. Query EvidenceEntry WHERE content_hash = hash LIMIT 1
       c. If found: reuse existing object_key (no upload), still create new
          EvidenceEntry row (chain must be maintained), log dedup event
       d. If not found: upload to MinIO as normal
  3. Uses global SessionLocalSync — no per-task engine creation.
  4. Saves chain_hash into every EvidenceEntry row (unchanged).
"""

import hashlib
import json
import time
from datetime import datetime
from typing import Optional
import structlog

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.slack_notifier import send_risk_alert_sync

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

    Uses get_db_session() context manager — session.close() is guaranteed
    on all code paths including partial failures mid-loop.

    Evidence deduplication:
      If content_hash already exists in evidence_entries, skip MinIO upload
      and reuse the existing object_key. A new EvidenceEntry row is still
      created to maintain the cryptographic chain integrity.
    """
    from app.db.database import get_db_session
    from app.models.control  import ControlResult
    from app.models.evidence  import EvidenceEntry
    from app.models.risk      import Risk
    from app.services.evidence_vault import evidence_vault
    from app.services.risk_engine    import risk_engine
    from sqlalchemy import select, desc

    with get_db_session() as session:
        try:
            # ── Step 1: Compute content hash BEFORE MinIO upload ──────────────
            content = (
                json.dumps(result.raw_output, indent=2, default=str)
                if isinstance(result.raw_output, (dict, list))
                else str(result.raw_output)
            )
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

            # ── Step 2: Check for duplicate blob ──────────────────────────────
            object_key   = None
            hmac_sig     = None
            dedup_hit    = False

            if settings.ENABLE_EVIDENCE_DEDUP:
                existing_entry = session.execute(
                    select(EvidenceEntry)
                    .where(EvidenceEntry.content_hash == content_hash)
                    .order_by(desc(EvidenceEntry.collected_at))
                    .limit(1)
                ).scalar_one_or_none()

                if existing_entry:
                    # Reuse existing MinIO blob — skip upload
                    object_key = existing_entry.raw_data_key
                    hmac_sig   = existing_entry.hmac_signature
                    dedup_hit  = True
                    logger.info(
                        "Evidence deduplicated — reusing existing blob",
                        control_id=result.control_id,
                        content_hash=content_hash[:12],
                        reused_key=object_key,
                    )

            # ── Step 3: Upload to MinIO if not a dedup hit ────────────────────
            if not dedup_hit:
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
                object_key = evidence_data["object_key"]
                hmac_sig   = evidence_data["hmac_signature"]

            # ── Step 4: Get previous entry for chain link ─────────────────────
            prev_entry = session.execute(
                select(EvidenceEntry)
                .where(EvidenceEntry.control_id == result.control_id)
                .order_by(desc(EvidenceEntry.collected_at))
                .limit(1)
            ).scalar_one_or_none()

            prev_content_hash = prev_entry.content_hash if prev_entry else None

            # ── Step 5: Compute chain hash and persist ────────────────────────
            chain_hash = evidence_vault.compute_chain_hash(content_hash, prev_content_hash)

            now       = datetime.utcnow()
            entry_ref = f"EVD-{now.strftime('%Y%m%d%H%M%S')}-{result.control_id}"

            db_evidence = EvidenceEntry(
                entry_ref           = entry_ref,
                control_id          = result.control_id,
                evidence_type       = "control_result",
                summary             = result.finding,
                raw_data_key        = object_key,
                content_hash        = content_hash,
                hmac_signature      = hmac_sig,
                previous_entry_hash = prev_content_hash,
                chain_hash          = chain_hash,
                chain_valid         = True,
                frameworks_covered  = ",".join(result.frameworks_failed or []),
                collected_by        = "automated_runner",
                collected_at        = now,
            )
            session.add(db_evidence)

            db_result = ControlResult(
                control_id            = result.control_id,
                control_name          = result.control_name,
                status                = result.status,
                passed                = result.passed,
                finding               = result.finding,
                raw_output            = json.dumps(result.raw_output),
                evidence_hash         = content_hash,
                evidence_key          = object_key,
                risk_contribution_gbp = result.risk_contribution_gbp,
                executed_at           = now,
                execution_duration_ms = duration_ms,
                runner_version        = "1.0.3",
            )
            session.add(db_result)

            if not result.passed and result.risk_contribution_gbp > 0:
                _auto_create_risk(session, result, risk_engine)

            session.commit()
            logger.info(
                "Stored result + evidence",
                control_id=result.control_id,
                entry_ref=entry_ref,
                chain_hash=chain_hash[:12],
                dedup_hit=dedup_hit,
            )

        except Exception as e:
            session.rollback()
            logger.error("Failed to store control result", error=str(e))


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

    # ─── Slack alert for critical control failure ──────────────────────────────
    if calc["severity"] in ("critical", "high") or calc["ale_mean_gbp"] >= 500_000:
        send_risk_alert_sync(
            event_type="control_failure",
            risk_ref=risk_ref,
            title=f"Control Failure: {result.control_name}",
            severity=calc["severity"],
            ale_gbp=calc["ale_mean_gbp"],
            detail=(
                f"Automated control runner detected a failure for `{result.control_id}`. "
                f"Finding: {result.finding}"
            ),
        )


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
