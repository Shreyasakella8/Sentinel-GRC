"""SENTINEL-GRC — Evidence Vault Endpoints

Performance improvement: list_evidence now supports cursor-based and OFFSET pagination.
Previously returned up to `limit` rows (default 100) loaded entirely into memory.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from typing import Optional

from app.core.security import require_permission
from app.core.config import settings
from app.db.database import get_db
from app.models.evidence import EvidenceEntry

router = APIRouter()


@router.get("/")
async def list_evidence(
    control_id: Optional[str] = None,
    # ── Cursor-based pagination (preferred) ───────────────────────────────
    cursor: Optional[int] = None,   # evidence_entry.id to start from (exclusive)
    # ── OFFSET pagination (fallback) ──────────────────────────────────────
    page:  int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("evidence")),
):
    """
    List evidence entries.

    Supports cursor-based (?cursor=<id>&limit=50) and OFFSET (?page=1&limit=50)
    pagination, controlled by ENABLE_PAGINATION feature flag. Both modes reduce
    memory usage — previously the entire result set was loaded at once.
    """
    base_query = select(EvidenceEntry).order_by(desc(EvidenceEntry.collected_at))
    if control_id:
        base_query = base_query.where(EvidenceEntry.control_id == control_id)

    def _entry_dict(e: EvidenceEntry) -> dict:
        return {
            "id":               e.id,
            "entry_ref":        e.entry_ref,
            "control_id":       e.control_id,
            "evidence_type":    e.evidence_type,
            "summary":          e.summary,
            "content_hash":     e.content_hash,
            "hmac_signature":   (e.hmac_signature[:16] + "...") if e.hmac_signature else None,
            "chain_valid":      e.chain_valid,
            "frameworks_covered": e.frameworks_covered,
            "collected_at":     e.collected_at.isoformat() if e.collected_at else None,
            "collected_by":     e.collected_by,
        }

    if not settings.ENABLE_PAGINATION:
        # Legacy behaviour — return up to original limit
        result  = await db.execute(base_query.limit(limit))
        entries = result.scalars().all()
        return {"total": len(entries), "entries": [_entry_dict(e) for e in entries]}

    # ── Cursor pagination ──────────────────────────────────────────────────
    if cursor is not None:
        cursor_query = select(EvidenceEntry).where(EvidenceEntry.id < cursor)
        if control_id:
            cursor_query = cursor_query.where(EvidenceEntry.control_id == control_id)
        cursor_query = cursor_query.order_by(desc(EvidenceEntry.id)).limit(limit + 1)

        result  = await db.execute(cursor_query)
        entries = result.scalars().all()

        has_more    = len(entries) > limit
        next_cursor = entries[limit - 1].id if has_more else None
        entries     = entries[:limit]

        total_result = await db.execute(
            select(func.count(EvidenceEntry.id))
            .where(EvidenceEntry.control_id == control_id if control_id else True)
        )
        total = total_result.scalar() or 0

        return {
            "total":       total,
            "limit":       limit,
            "next_cursor": next_cursor,
            "entries":     [_entry_dict(e) for e in entries],
        }

    # ── OFFSET pagination ──────────────────────────────────────────────────
    limit  = min(limit, 200)
    offset = (page - 1) * limit

    count_query = select(func.count(EvidenceEntry.id))
    if control_id:
        count_query = count_query.where(EvidenceEntry.control_id == control_id)
    total_result = await db.execute(count_query)
    total        = total_result.scalar() or 0

    result  = await db.execute(base_query.offset(offset).limit(limit))
    entries = result.scalars().all()

    return {
        "total":   total,
        "page":    page,
        "limit":   limit,
        "pages":   (total + limit - 1) // limit,
        "entries": [_entry_dict(e) for e in entries],
    }


@router.get("/verify/{entry_ref}")
async def verify_evidence(
    entry_ref: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("evidence")),
):
    result = await db.execute(select(EvidenceEntry).where(EvidenceEntry.entry_ref == entry_ref))
    entry  = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Evidence entry not found")

    from app.services.evidence_vault import evidence_vault
    is_valid = evidence_vault.verify_signature(
        entry.content_hash, entry.collected_at.isoformat(), entry.control_id, entry.hmac_signature
    )
    return {
        "entry_ref":      entry_ref,
        "integrity_valid": is_valid,
        "chain_valid":    entry.chain_valid,
        "content_hash":   entry.content_hash,
        "collected_at":   entry.collected_at.isoformat() if entry.collected_at else None,
        "message": "Evidence integrity verified — tamper-free" if is_valid else "WARNING: Evidence integrity check FAILED",
    }
