"""SENTINEL-GRC — Threat Intelligence Endpoints"""
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.security import require_permission
from app.db.database import get_db
from app.models.threat import ThreatEvent

router = APIRouter()

@router.get("/")
async def list_threats(
    severity: str = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("threats")),
):
    query = select(ThreatEvent).order_by(desc(ThreatEvent.detected_at)).limit(limit)
    if severity:
        query = query.where(ThreatEvent.severity == severity)
    result = await db.execute(query)
    threats = result.scalars().all()
    return {
        "total": len(threats),
        "threats": [
            {
                "id": t.id,
                "source": t.source,
                "external_id": t.external_id,
                "title": t.title,
                "severity": t.severity,
                "cvss_score": t.cvss_score,
                "is_known_exploited": t.is_known_exploited,
                "affected_products": t.affected_products,
                "assets_affected": t.assets_affected,
                "risk_delta_gbp": t.risk_delta_gbp,
                "patch_available": t.patch_available,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in threats
        ],
    }

@router.post("/refresh")
async def refresh_threat_feeds(
    background_tasks: BackgroundTasks,
    current_user=Depends(require_permission("threats")),
):
    from app.tasks.threat_intelligence import fetch_nvd_cves, fetch_cisa_kev
    t1 = fetch_nvd_cves.delay()
    t2 = fetch_cisa_kev.delay()
    return {"message": "Threat intelligence refresh queued", "tasks": [t1.id, t2.id]}
