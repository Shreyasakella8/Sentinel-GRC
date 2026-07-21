"""SENTINEL-GRC — Controls Endpoints

Performance fixes applied:
  1. N+1 query replaced: previously ran two queries (subq + join). Now uses a
     single row_number() window function to fetch the latest result per control
     in one round-trip.
  2. TTL catalog cache: ControlCatalog (12 static rows) is cached for 1 hour.
     Previously fetched from DB on every GET /controls/ request.
"""

import time
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text
from sqlalchemy.orm import aliased

from app.core.security import require_permission
from app.db.database import get_db
from app.models.control import ControlResult
from app.models.compliance import ControlCatalog as Catalog

router = APIRouter()

# ── TTL cache for the static control catalog ──────────────────────────────────
# The catalog has 12 rows and changes only during schema migrations.
# Hitting PostgreSQL for it on every dashboard refresh is pure waste.
_catalog_cache: Optional[dict] = None
_catalog_cache_ts: float = 0.0
_CATALOG_TTL_SECONDS: int = 3600   # 1 hour


async def _get_catalog_cached(db: AsyncSession) -> dict:
    """
    Returns the control catalog as {control_id: Catalog} dict.
    Refreshes from DB at most once per hour.
    Thread-safe for asyncio: single-threaded event loop prevents races.
    """
    global _catalog_cache, _catalog_cache_ts

    if _catalog_cache is not None and (time.monotonic() - _catalog_cache_ts) < _CATALOG_TTL_SECONDS:
        return _catalog_cache

    result = await db.execute(select(Catalog))
    _catalog_cache = {c.control_id: c for c in result.scalars().all()}
    _catalog_cache_ts = time.monotonic()
    return _catalog_cache


@router.get("/")
async def list_controls(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("controls")),
):
    """
    List all controls with their latest result.

    Query strategy: single window function (row_number OVER PARTITION BY control_id
    ORDER BY executed_at DESC) fetches the latest result per control in one round-trip.
    Previously this used a subquery + join = two round-trips.
    Catalog is served from a 1-hour TTL in-memory cache.
    """
    # ── 1. Load catalog from cache (O(1) after first load) ────────────────────
    catalog = await _get_catalog_cached(db)

    # ── 2. Single-pass window query for latest results ─────────────────────────
    # row_number() OVER (PARTITION BY control_id ORDER BY executed_at DESC) = 1
    # selects exactly the most recent row per control without a subquery join.
    ranked = (
        select(
            ControlResult,
            func.row_number().over(
                partition_by=ControlResult.control_id,
                order_by=desc(ControlResult.executed_at),
            ).label("rn"),
        )
        .subquery()
    )

    latest_alias = aliased(ControlResult, ranked)
    result = await db.execute(
        select(latest_alias).where(ranked.c.rn == 1)
    )
    latest = {r.control_id: r for r in result.scalars().all()}

    # ── 3. Merge catalog + latest result ──────────────────────────────────────
    controls = []
    for ctrl_id, ctrl in catalog.items():
        result_row = latest.get(ctrl_id)
        controls.append({
            "control_id":      ctrl.control_id,
            "name":            ctrl.name,
            "description":     ctrl.description,
            "category":        ctrl.category,
            "severity":        ctrl.severity,
            "iso27001_clause": ctrl.iso27001_clause,
            "nist_csf":        ctrl.nist_csf,
            "soc2_criteria":   ctrl.soc2_criteria,
            "cyber_essentials": ctrl.cyber_essentials,
            "frequency_hours": ctrl.frequency_hours,
            "fine_exposure_gbp": ctrl.fine_exposure_gbp,
            "latest_result": {
                "status":        result_row.status,
                "passed":        result_row.passed,
                "finding":       result_row.finding,
                "executed_at":   result_row.executed_at.isoformat() if result_row.executed_at else None,
                "evidence_hash": result_row.evidence_hash,
            } if result_row else None,
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
                "id":                     r.id,
                "status":                 r.status,
                "passed":                 r.passed,
                "finding":                r.finding,
                "evidence_hash":          r.evidence_hash,
                "risk_contribution_gbp":  r.risk_contribution_gbp,
                "executed_at":            r.executed_at.isoformat() if r.executed_at else None,
                "duration_ms":            r.execution_duration_ms,
            }
            for r in history
        ],
    }
