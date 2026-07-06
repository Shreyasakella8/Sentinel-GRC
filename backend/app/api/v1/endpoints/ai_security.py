"""
SENTINEL-GRC — AI Security Endpoints
/ai-security/scan        — guardrail scan
/ai-security/logs        — audit log of all scans
/ai-security/assessments — NIST AI RMF assessments
/ai-security/policies    — AI usage policies
/ai-security/stats       — dashboard metrics
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.security import require_permission, get_current_user
from app.db.database import get_db
from app.models.ai_security import AIGuardrailLog, AIRiskAssessment, AISecurityPolicy
from app.services.ai_guard import ai_guard

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    text:       str
    context:    str = "user_input"
    session_id: Optional[str] = None


class AssessmentCreate(BaseModel):
    ai_system_name:    str
    ai_system_version: Optional[str] = None
    ai_system_type:    str = "llm"
    deployment_env:    str = "production"
    vendor:            Optional[str] = None
    # GOVERN
    gov_policies_defined:      float = 0.0
    gov_roles_assigned:        float = 0.0
    gov_accountability:        float = 0.0
    gov_third_party_oversight: float = 0.0
    # MAP
    map_context_established:   float = 0.0
    map_impact_assessment:     float = 0.0
    map_bias_identified:       float = 0.0
    map_data_lineage:          float = 0.0
    # MEASURE
    msr_accuracy:              float = 0.0
    msr_robustness:            float = 0.0
    msr_fairness:              float = 0.0
    msr_explainability:        float = 0.0
    msr_privacy:               float = 0.0
    msr_security:              float = 0.0
    msr_adversarial_testing:   float = 0.0
    # MANAGE
    mng_incident_response:     float = 0.0
    mng_monitoring:            float = 0.0
    mng_decommission_plan:     float = 0.0
    mng_human_oversight:       float = 0.0
    notes: Optional[str] = None


class PolicyCreate(BaseModel):
    title:       str
    category:    str = "acceptable_use"
    description: Optional[str] = None
    content:     Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────────

def _compute_scores(data: AssessmentCreate) -> dict:
    """Weighted composite score per NIST AI RMF quadrant."""
    govern  = (data.gov_policies_defined + data.gov_roles_assigned +
               data.gov_accountability + data.gov_third_party_oversight) / 4.0
    mapping = (data.map_context_established + data.map_impact_assessment +
               data.map_bias_identified + data.map_data_lineage) / 4.0
    measure = (data.msr_accuracy + data.msr_robustness + data.msr_fairness +
               data.msr_explainability + data.msr_privacy + data.msr_security +
               data.msr_adversarial_testing) / 7.0
    manage  = (data.mng_incident_response + data.mng_monitoring +
               data.mng_decommission_plan + data.mng_human_oversight) / 4.0

    # NIST weighting: Measure and Manage are heavier
    composite = (govern * 0.20) + (mapping * 0.20) + (measure * 0.35) + (manage * 0.25)

    tier = (
        "critical" if composite < 0.25 else
        "high"     if composite < 0.50 else
        "medium"   if composite < 0.75 else
        "low"
    )
    return {
        "govern_score":    round(govern,    3),
        "map_score":       round(mapping,   3),
        "measure_score":   round(measure,   3),
        "manage_score":    round(manage,    3),
        "composite_score": round(composite, 3),
        "risk_tier":       tier,
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/scan")
async def scan_input(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Run a text through the 5-stage AI guardrail pipeline.
    Logs every scan to the immutable audit table.
    """
    result = ai_guard.scan(payload.text, context=payload.context)

    # Persist scan log
    log = AIGuardrailLog(
        session_id     = payload.session_id,
        context        = payload.context,
        input_hash     = result.input_hash,
        input_preview  = payload.text[:500],
        allowed        = result.allowed,
        classification = result.classification,
        risk_score     = result.risk_score,
        finding_count  = len(result.findings),
        findings       = result.findings,
        redacted       = result.redacted_input is not None,
        processing_ms  = result.processing_ms,
        user_id        = current_user.id,
        user_email     = current_user.email,
        scanned_at     = datetime.utcnow(),
    )
    db.add(log)
    await db.commit()

    return result.to_dict()


@router.post("/scan-output")
async def scan_model_output(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """DLP scan on model output before it reaches the user."""
    result = ai_guard.scan_output(payload.text)

    log = AIGuardrailLog(
        session_id     = payload.session_id,
        context        = "model_output",
        input_hash     = result.input_hash,
        input_preview  = payload.text[:500],
        allowed        = result.allowed,
        classification = result.classification,
        risk_score     = result.risk_score,
        finding_count  = len(result.findings),
        findings       = result.findings,
        redacted       = result.redacted_input is not None,
        processing_ms  = result.processing_ms,
        user_id        = current_user.id,
        user_email     = current_user.email,
        scanned_at     = datetime.utcnow(),
    )
    db.add(log)
    await db.commit()

    return result.to_dict()


@router.get("/logs")
async def list_scan_logs(
    blocked_only: bool = False,
    limit:        int  = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("threats")),
):
    """Audit log of all guardrail scans with optional blocked-only filter."""
    query = (
        select(AIGuardrailLog)
        .order_by(desc(AIGuardrailLog.scanned_at))
        .limit(limit)
    )
    if blocked_only:
        query = query.where(AIGuardrailLog.allowed == False)

    result = await db.execute(query)
    logs   = result.scalars().all()

    return {
        "total": len(logs),
        "logs": [
            {
                "id":             l.id,
                "session_id":     l.session_id,
                "context":        l.context,
                "allowed":        l.allowed,
                "classification": l.classification,
                "risk_score":     l.risk_score,
                "finding_count":  l.finding_count,
                "findings":       l.findings,
                "redacted":       l.redacted,
                "processing_ms":  l.processing_ms,
                "user_email":     l.user_email,
                "input_preview":  l.input_preview,
                "scanned_at":     l.scanned_at.isoformat() if l.scanned_at else None,
            }
            for l in logs
        ],
    }


@router.get("/stats")
async def get_ai_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("dashboard")),
):
    """Dashboard metrics for the AI Security module."""
    since = datetime.utcnow() - timedelta(days=30)

    total_scans  = await db.execute(
        select(func.count(AIGuardrailLog.id))
        .where(AIGuardrailLog.scanned_at >= since)
    )
    blocked      = await db.execute(
        select(func.count(AIGuardrailLog.id))
        .where(AIGuardrailLog.scanned_at >= since, AIGuardrailLog.allowed == False)
    )
    by_class     = await db.execute(
        select(AIGuardrailLog.classification, func.count(AIGuardrailLog.id))
        .where(AIGuardrailLog.scanned_at >= since)
        .group_by(AIGuardrailLog.classification)
    )
    assessments  = await db.execute(select(func.count(AIRiskAssessment.id)))
    policies     = await db.execute(
        select(func.count(AISecurityPolicy.id))
        .where(AISecurityPolicy.status == "active")
    )

    total  = total_scans.scalar() or 0
    bl     = blocked.scalar() or 0
    block_rate = round((bl / total * 100) if total > 0 else 0, 1)

    return {
        "period_days":       30,
        "total_scans":       total,
        "blocked_scans":     bl,
        "block_rate_pct":    block_rate,
        "by_classification": {row[0]: row[1] for row in by_class.all()},
        "total_assessments": assessments.scalar() or 0,
        "active_policies":   policies.scalar() or 0,
    }


@router.get("/assessments")
async def list_assessments(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    result      = await db.execute(select(AIRiskAssessment).order_by(desc(AIRiskAssessment.created_at)))
    assessments = result.scalars().all()
    return {
        "total": len(assessments),
        "assessments": [
            {
                "id":               a.id,
                "assessment_ref":   a.assessment_ref,
                "ai_system_name":   a.ai_system_name,
                "ai_system_type":   a.ai_system_type,
                "deployment_env":   a.deployment_env,
                "vendor":           a.vendor,
                "composite_score":  a.composite_score,
                "govern_score":     a.govern_score,
                "map_score":        a.map_score,
                "measure_score":    a.measure_score,
                "manage_score":     a.manage_score,
                "risk_tier":        a.risk_tier,
                "status":           a.status,
                "created_at":       a.created_at.isoformat() if a.created_at else None,
            }
            for a in assessments
        ],
    }


@router.post("/assessments")
async def create_assessment(
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    from sqlalchemy import func as sqlfunc
    count_r = await db.execute(select(sqlfunc.count(AIRiskAssessment.id)))
    count   = count_r.scalar() or 0
    ref     = f"AIRA-{str(count + 1).zfill(4)}"

    scores = _compute_scores(payload)

    a = AIRiskAssessment(
        assessment_ref           = ref,
        ai_system_name           = payload.ai_system_name,
        ai_system_version        = payload.ai_system_version,
        ai_system_type           = payload.ai_system_type,
        deployment_env           = payload.deployment_env,
        vendor                   = payload.vendor,
        gov_policies_defined     = payload.gov_policies_defined,
        gov_roles_assigned       = payload.gov_roles_assigned,
        gov_accountability       = payload.gov_accountability,
        gov_third_party_oversight= payload.gov_third_party_oversight,
        map_context_established  = payload.map_context_established,
        map_impact_assessment    = payload.map_impact_assessment,
        map_bias_identified      = payload.map_bias_identified,
        map_data_lineage         = payload.map_data_lineage,
        msr_accuracy             = payload.msr_accuracy,
        msr_robustness           = payload.msr_robustness,
        msr_fairness             = payload.msr_fairness,
        msr_explainability       = payload.msr_explainability,
        msr_privacy              = payload.msr_privacy,
        msr_security             = payload.msr_security,
        msr_adversarial_testing  = payload.msr_adversarial_testing,
        mng_incident_response    = payload.mng_incident_response,
        mng_monitoring           = payload.mng_monitoring,
        mng_decommission_plan    = payload.mng_decommission_plan,
        mng_human_oversight      = payload.mng_human_oversight,
        notes                    = payload.notes,
        assessed_by_id           = current_user.id,
        **scores,
    )
    db.add(a)
    await db.commit()

    return {"assessment_ref": ref, **scores}


@router.get("/policies")
async def list_ai_policies(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("governance")),
):
    result   = await db.execute(select(AISecurityPolicy).order_by(desc(AISecurityPolicy.created_at)))
    policies = result.scalars().all()
    return {
        "total": len(policies),
        "policies": [
            {
                "id":          p.id,
                "policy_ref":  p.policy_ref,
                "title":       p.title,
                "category":    p.category,
                "status":      p.status,
                "version":     p.version,
                "description": p.description,
                "created_at":  p.created_at.isoformat() if p.created_at else None,
            }
            for p in policies
        ],
    }


@router.post("/policies")
async def create_ai_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("governance")),
):
    from sqlalchemy import func as sqlfunc
    count_r = await db.execute(select(sqlfunc.count(AISecurityPolicy.id)))
    count   = count_r.scalar() or 0
    ref     = f"AIPL-{str(count + 1).zfill(4)}"

    p = AISecurityPolicy(
        policy_ref  = ref,
        title       = payload.title,
        category    = payload.category,
        description = payload.description,
        content     = payload.content,
        status      = "draft",
        author_id   = current_user.id,
    )
    db.add(p)
    await db.commit()
    return {"policy_ref": ref, "status": "draft"}
