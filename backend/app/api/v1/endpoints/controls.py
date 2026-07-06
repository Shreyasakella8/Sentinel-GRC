"""SENTINEL-GRC — Controls Endpoints"""

from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional

from app.core.security import require_permission
from app.db.database import get_db
from app.models.control import ControlResult
from app.models.compliance import ControlCatalog as Catalog

router = APIRouter()


@router.get("/")
async def list_controls(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("controls")),
):
    """List all controls with their latest result."""
    catalog_result = await db.execute(select(Catalog))
    catalog = {c.control_id: c for c in catalog_result.scalars().all()}

    subq = (
        select(
            ControlResult.control_id,
            func.max(ControlResult.executed_at).label("latest"),
        )
        .group_by(ControlResult.control_id)
        .subquery()
    )

    results_query = await db.execute(
        select(ControlResult).join(
            subq,
            (ControlResult.control_id == subq.c.control_id)
            & (ControlResult.executed_at == subq.c.latest),
        )
    )
    latest = {r.control_id: r for r in results_query.scalars().all()}

    controls = []
    for ctrl_id, ctrl in catalog.items():
        result = latest.get(ctrl_id)
        controls.append({
            "control_id": ctrl.control_id,
            "name": ctrl.name,
            "description": ctrl.description,
            "category": ctrl.category,
            "severity": ctrl.severity,
            "iso27001_clause": ctrl.iso27001_clause,
            "nist_csf": ctrl.nist_csf,
            "soc2_criteria": ctrl.soc2_criteria,
            "cyber_essentials": ctrl.cyber_essentials,
            "frequency_hours": ctrl.frequency_hours,
            "fine_exposure_gbp": ctrl.fine_exposure_gbp,
            "latest_result": {
                "status": result.status,
                "passed": result.passed,
                "finding": result.finding,
                "executed_at": result.executed_at.isoformat() if result.executed_at else None,
                "evidence_hash": result.evidence_hash,
            } if result else None,
        })

    return {"total": len(controls), "controls": controls}


@router.post("/{control_id}/run")
async def run_control_on_demand(
    control_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("controls")),
):
    """Trigger an on-demand control run."""
    from app.tasks.control_sweep import run_single_control_task
    task = run_single_control_task.delay(control_id)
    return {"message": f"Control {control_id} queued for execution", "task_id": task.id}


@router.get("/history/{control_id}")
async def get_control_history(
    control_id: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("controls")),
):
    """Get execution history for a specific control."""
    result = await db.execute(
        select(ControlResult)
        .where(ControlResult.control_id == control_id)
        .order_by(desc(ControlResult.executed_at))
        .limit(limit)
    )
    history = result.scalars().all()

    pass_rate = 0
    if history:
        pass_rate = round(sum(1 for r in history if r.passed) / len(history) * 100)

    return {
        "control_id": control_id,
        "pass_rate_percent": pass_rate,
        "history": [
            {
                "id": r.id,
                "status": r.status,
                "passed": r.passed,
                "finding": r.finding,
                "evidence_hash": r.evidence_hash,
                "risk_contribution_gbp": r.risk_contribution_gbp,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
                "duration_ms": r.execution_duration_ms,
            }
            for r in history
        ],
    }
