"""SENTINEL-GRC — Risk Register Endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.core.security import get_current_user, require_permission
from app.db.database import get_db
from app.models.risk import Risk, RiskScore
from app.services.risk_engine import risk_engine

router = APIRouter()


class RiskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str = "cyber"
    asset_name: Optional[str] = None
    asset_type: str = "server"
    asset_value_gbp: Optional[float] = None
    data_sensitivity: str = "internal"
    threat_event_frequency: float
    vulnerability_probability: float
    primary_loss_magnitude_gbp: float
    secondary_loss_magnitude_gbp: float = 0
    regulatory_fine_exposure_gbp: float = 0
    treatment: Optional[str] = None
    treatment_plan: Optional[str] = None


class RiskUpdate(BaseModel):
    status: Optional[str] = None
    treatment: Optional[str] = None
    treatment_plan: Optional[str] = None
    treatment_due_date: Optional[datetime] = None
    owner_id: Optional[int] = None


@router.get("/")
async def list_risks(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    """List all risks from the register."""
    query = select(Risk).order_by(desc(Risk.annualised_loss_expectancy_gbp))
    if status:
        query = query.where(Risk.status == status)
    if severity:
        query = query.where(Risk.severity == severity)

    result = await db.execute(query)
    risks = result.scalars().all()

    def fmt(v):
        if v is None:
            return "£0"
        if v >= 1_000_000:
            return f"£{v/1_000_000:.1f}M"
        elif v >= 1_000:
            return f"£{v/1_000:.0f}K"
        return f"£{int(v):,}"

    return {
        "total": len(risks),
        "risks": [
            {
                "id": r.id,
                "risk_ref": r.risk_ref,
                "title": r.title,
                "description": r.description,
                "category": r.category,
                "severity": r.severity,
                "status": r.status,
                "ale_formatted": fmt(r.annualised_loss_expectancy_gbp),
                "ale_gbp": r.annualised_loss_expectancy_gbp,
                "ale_90th_gbp": r.ale_90th_percentile_gbp,
                "ale_90th_formatted": fmt(r.ale_90th_percentile_gbp),
                "exploitation_probability_12m": r.exploitation_probability_12m,
                "treatment": r.treatment,
                "escalated": r.escalated,
                "board_approval_needed": r.board_threshold_exceeded and not r.board_approved,
                "frameworks_impacted": r.frameworks_impacted,
                "source": r.source,
                "linked_cve": r.linked_cve,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "owner_id": r.owner_id,
            }
            for r in risks
        ],
    }


@router.post("/")
async def create_risk(
    payload: RiskCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    """Create a new risk with FAIR Monte Carlo calculation."""
    from sqlalchemy import func

    # Generate risk ref
    count_result = await db.execute(select(func.count(Risk.id)))
    count = count_result.scalar() or 0
    risk_ref = f"RISK-{str(count + 1).zfill(4)}"

    # Run FAIR calculation
    calc = risk_engine.calculate_risk(
        asset_value_gbp=payload.asset_value_gbp or 500_000,
        threat_event_frequency=payload.threat_event_frequency,
        vulnerability_probability=payload.vulnerability_probability,
        primary_loss_magnitude_gbp=payload.primary_loss_magnitude_gbp,
        secondary_loss_magnitude_gbp=payload.secondary_loss_magnitude_gbp,
        regulatory_fine_exposure_gbp=payload.regulatory_fine_exposure_gbp,
        data_sensitivity=payload.data_sensitivity,
        asset_type=payload.asset_type,
    )

    risk = Risk(
        risk_ref=risk_ref,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        asset_name=payload.asset_name,
        asset_type=payload.asset_type,
        asset_value_gbp=payload.asset_value_gbp,
        data_sensitivity=payload.data_sensitivity,
        threat_event_frequency=payload.threat_event_frequency,
        vulnerability_probability=payload.vulnerability_probability,
        primary_loss_magnitude_gbp=payload.primary_loss_magnitude_gbp,
        secondary_loss_magnitude_gbp=payload.secondary_loss_magnitude_gbp,
        regulatory_fine_exposure_gbp=payload.regulatory_fine_exposure_gbp,
        annualised_loss_expectancy_gbp=calc["ale_mean_gbp"],
        ale_10th_percentile_gbp=calc["ale_10th_percentile_gbp"],
        ale_90th_percentile_gbp=calc["ale_90th_percentile_gbp"],
        exploitation_probability_12m=calc["exploitation_probability_12m"],
        last_monte_carlo_run=datetime.utcnow(),
        severity=calc["severity"],
        status="open",
        treatment=payload.treatment,
        treatment_plan=payload.treatment_plan,
        raised_by_id=current_user.id,
        source="manual",
    )
    db.add(risk)
    await db.flush()

    # Snapshot initial score
    score = RiskScore(
        risk_id=risk.id,
        ale_gbp=calc["ale_mean_gbp"],
        severity=calc["severity"],
        trigger="created",
    )
    db.add(score)
    await db.commit()

    return {
        "risk_ref": risk_ref,
        "id": risk.id,
        "ale_mean_gbp": calc["ale_mean_gbp"],
        "ale_90th_gbp": calc["ale_90th_percentile_gbp"],
        "severity": calc["severity"],
        "exploitation_probability_12m": calc["exploitation_probability_12m"],
        "narrative": calc["narrative"],
        "loss_exceedance_curve": calc["loss_exceedance_curve"],
    }


@router.get("/{risk_id}")
async def get_risk(
    risk_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    """Get full risk detail with FAIR narrative and loss exceedance curve."""
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    # Get score history for trend chart
    score_history = await db.execute(
        select(RiskScore)
        .where(RiskScore.risk_id == risk_id)
        .order_by(RiskScore.recorded_at)
    )
    scores = score_history.scalars().all()

    return {
        "risk": {
            "id": risk.id,
            "risk_ref": risk.risk_ref,
            "title": risk.title,
            "description": risk.description,
            "category": risk.category,
            "severity": risk.severity,
            "status": risk.status,
            "asset_name": risk.asset_name,
            "asset_type": risk.asset_type,
            "data_sensitivity": risk.data_sensitivity,
            "threat_event_frequency": risk.threat_event_frequency,
            "vulnerability_probability": risk.vulnerability_probability,
            "ale_mean_gbp": risk.annualised_loss_expectancy_gbp,
            "ale_10th_gbp": risk.ale_10th_percentile_gbp,
            "ale_90th_gbp": risk.ale_90th_percentile_gbp,
            "exploitation_probability_12m": risk.exploitation_probability_12m,
            "treatment": risk.treatment,
            "treatment_plan": risk.treatment_plan,
            "treatment_due_date": risk.treatment_due_date.isoformat() if risk.treatment_due_date else None,
            "escalated": risk.escalated,
            "board_approved": risk.board_approved,
            "frameworks_impacted": risk.frameworks_impacted,
            "linked_cve": risk.linked_cve,
            "source": risk.source,
            "created_at": risk.created_at.isoformat() if risk.created_at else None,
        },
        "score_history": [
            {
                "date": s.recorded_at.isoformat(),
                "ale_gbp": s.ale_gbp,
                "severity": s.severity,
                "trigger": s.trigger,
            }
            for s in scores
        ],
    }


@router.patch("/{risk_id}")
async def update_risk(
    risk_id: int,
    payload: RiskUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("risks")),
):
    """Update risk status or treatment. Enforces Segregation of Duties."""
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    # Segregation of Duties: raiser cannot close, accept, or transfer their own risk
    # FIX: Expanded to cover 'accepted' and 'transferred' which bypass the original check
    SOD_BLOCKED_STATUSES = {"closed", "accepted", "transferred"}
    if payload.status in SOD_BLOCKED_STATUSES and risk.raised_by_id == current_user.id:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Segregation of Duties violation: the person who raised a risk "
                f"cannot set it to '{payload.status}'. Another user must approve this action."
            ),
        )

    if payload.status:
        risk.status = payload.status
        if payload.status == "closed":
            risk.closed_at = datetime.utcnow()
    if payload.treatment:
        risk.treatment = payload.treatment
    if payload.treatment_plan:
        risk.treatment_plan = payload.treatment_plan
    if payload.treatment_due_date:
        risk.treatment_due_date = payload.treatment_due_date
    if payload.owner_id:
        risk.owner_id = payload.owner_id

    await db.commit()
    return {"message": "Risk updated", "risk_ref": risk.risk_ref}
