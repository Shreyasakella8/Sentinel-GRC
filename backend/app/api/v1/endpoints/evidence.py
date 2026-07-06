"""SENTINEL-GRC — Evidence Vault Endpoints"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.security import require_permission
from app.db.database import get_db
from app.models.evidence import EvidenceEntry

router = APIRouter()

@router.get("/")
async def list_evidence(
    control_id: str = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("evidence")),
):
    query = select(EvidenceEntry).order_by(desc(EvidenceEntry.collected_at)).limit(limit)
    if control_id:
        query = query.where(EvidenceEntry.control_id == control_id)
    result = await db.execute(query)
    entries = result.scalars().all()
    return {
        "total": len(entries),
        "entries": [
            {
                "id": e.id,
                "entry_ref": e.entry_ref,
                "control_id": e.control_id,
                "evidence_type": e.evidence_type,
                "summary": e.summary,
                "content_hash": e.content_hash,
                "hmac_signature": (e.hmac_signature[:16] + "...") if e.hmac_signature else None,
                "chain_valid": e.chain_valid,
                "frameworks_covered": e.frameworks_covered,
                "collected_at": e.collected_at.isoformat() if e.collected_at else None,
                "collected_by": e.collected_by,
            }
            for e in entries
        ],
    }

@router.get("/verify/{entry_ref}")
async def verify_evidence(
    entry_ref: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("evidence")),
):
    result = await db.execute(select(EvidenceEntry).where(EvidenceEntry.entry_ref == entry_ref))
    entry = result.scalar_one_or_none()
    if not entry:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Evidence entry not found")

    from app.services.evidence_vault import evidence_vault
    is_valid = evidence_vault.verify_signature(
        entry.content_hash, entry.collected_at.isoformat(), entry.control_id, entry.hmac_signature
    )
    return {
        "entry_ref": entry_ref,
        "integrity_valid": is_valid,
        "chain_valid": entry.chain_valid,
        "content_hash": entry.content_hash,
        "collected_at": entry.collected_at.isoformat() if entry.collected_at else None,
        "message": "Evidence integrity verified — tamper-free" if is_valid else "WARNING: Evidence integrity check FAILED",
    }
