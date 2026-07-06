"""
SENTINEL-GRC — Governance Workflow Endpoints
Role-based transition guard: only ciso can push a policy to 'published'.
Risk Owner and below are blocked from bypassing the approval chain.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.core.security import require_permission, get_current_user, UserRole
from app.db.database import get_db
from app.models.governance import (
    Policy, PolicyHistory, AuditPlan, AuditFinding, GovernanceAction
)

router = APIRouter()

# State machine — which states each role may transition TO
POLICY_TRANSITIONS = {
    "draft":            ["legal_review"],
    "legal_review":     ["ciso_approval", "draft"],
    "ciso_approval":    ["published", "legal_review"],
    "published":        ["scheduled_review"],
    "scheduled_review": ["draft", "retired"],
    "retired":          [],
}

# Only CISO may push to these terminal/approval states
CISO_ONLY_TARGET_STATES = {"published", "ciso_approval"}


class PolicyCreate(BaseModel):
    title:               str
    description:         Optional[str] = None
    category:            str           = "information_security"
    content:             Optional[str] = None
    framework_references: list         = []


class PolicyTransition(BaseModel):
    to_status: str
    comment:   Optional[str] = None


@router.get("/policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("governance")),
):
    result   = await db.execute(select(Policy).order_by(desc(Policy.created_at)))
    policies = result.scalars().all()
    return {"policies": [
        {
            "id":              p.id,
            "policy_ref":      p.policy_ref,
            "title":           p.title,
            "category":        p.category,
            "status":          p.status,
            "version":         p.version,
            "review_due_date": p.review_due_date.isoformat() if p.review_due_date else None,
            "created_at":      p.created_at.isoformat() if p.created_at else None,
        }
        for p in policies
    ]}


@router.post("/policies")
async def create_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("governance")),
):
    from sqlalchemy import func
    count_result = await db.execute(select(func.count(Policy.id)))
    count        = count_result.scalar() or 0
    policy_ref   = f"POL-{str(count + 1).zfill(4)}"

    policy = Policy(
        policy_ref           = policy_ref,
        title                = payload.title,
        description          = payload.description,
        category             = payload.category,
        content              = payload.content,
        framework_references = payload.framework_references,
        status               = "draft",
        author_id            = current_user.id,
    )
    db.add(policy)
    await db.commit()
    return {"policy_ref": policy_ref, "status": "draft"}


@router.post("/policies/{policy_id}/transition")
async def transition_policy(
    policy_id: int,
    payload: PolicyTransition,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("governance")),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    # State machine validation
    allowed = POLICY_TRANSITIONS.get(policy.status, [])
    if payload.to_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition '{policy.status}' → '{payload.to_status}'. Allowed: {allowed}",
        )

    # Role guard: only CISO may approve or publish
    if payload.to_status in CISO_ONLY_TARGET_STATES:
        if current_user.role != UserRole.CISO.value:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Only the CISO may transition a policy to '{payload.to_status}'. "
                    f"Your role ({current_user.role}) is not authorised."
                ),
            )

    db.add(PolicyHistory(
        policy_id      = policy.id,
        from_status    = policy.status,
        to_status      = payload.to_status,
        changed_by_id  = current_user.id,
        comment        = payload.comment,
    ))

    policy.status = payload.to_status
    if payload.to_status == "published":
        policy.published_at = datetime.utcnow()
    elif payload.to_status == "retired":
        policy.retired_at = datetime.utcnow()

    await db.commit()
    return {"message": f"Policy transitioned to '{payload.to_status}'", "policy_ref": policy.policy_ref}


@router.get("/audits")
async def list_audits(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("audit")),
):
    result = await db.execute(select(AuditPlan).order_by(desc(AuditPlan.scheduled_start)))
    audits = result.scalars().all()
    return {"audits": [
        {
            "id":              a.id,
            "audit_ref":       a.audit_ref,
            "title":           a.title,
            "framework":       a.framework,
            "audit_type":      a.audit_type,
            "status":          a.status,
            "scheduled_start": a.scheduled_start.isoformat() if a.scheduled_start else None,
            "scheduled_end":   a.scheduled_end.isoformat() if a.scheduled_end else None,
        }
        for a in audits
    ]}


@router.get("/findings")
async def list_findings(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("audit")),
):
    result   = await db.execute(select(AuditFinding).order_by(desc(AuditFinding.created_at)))
    findings = result.scalars().all()
    return {"findings": [
        {
            "id":               f.id,
            "finding_ref":      f.finding_ref,
            "title":            f.title,
            "severity":         f.severity,
            "status":           f.status,
            "sla_breached":     f.sla_breached,
            "remediation_due":  f.remediation_due.isoformat() if f.remediation_due else None,
        }
        for f in findings
    ]}
