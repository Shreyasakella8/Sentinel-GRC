"""
SENTINEL-GRC — Reports Endpoints
Uses the global SessionLocalSync (same pool as Celery tasks) instead of
creating a new engine on every request — this was a leftover bug from
before the v2 connection-pool fix.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
import os

from app.core.security import require_permission
from app.db.database import get_db, SessionLocalSync
from app.core.config import settings

router = APIRouter()


@router.post("/board")
async def generate_board_report(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("reports")),
):
    from app.services.report_generator import generate_board_report
    sync_db = SessionLocalSync()
    try:
        path = generate_board_report(sync_db)
    finally:
        sync_db.close()
    filename = os.path.basename(path)
    return {"message": "Board report generated", "filename": filename, "url": f"/reports/{filename}"}


@router.post("/auditor")
async def generate_auditor_report(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("reports")),
):
    from app.services.report_generator import generate_auditor_report
    sync_db = SessionLocalSync()
    try:
        path = generate_auditor_report(sync_db)
    finally:
        sync_db.close()
    filename = os.path.basename(path)
    return {"message": "Auditor report generated", "filename": filename, "url": f"/reports/{filename}"}


@router.post("/technical")
async def generate_technical_report(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("reports")),
):
    from app.services.report_generator import generate_technical_report
    sync_db = SessionLocalSync()
    try:
        path = generate_technical_report(sync_db)
    finally:
        sync_db.close()
    filename = os.path.basename(path)
    return {"message": "Technical report generated", "filename": filename, "url": f"/reports/{filename}"}


@router.get("/list")
async def list_reports(current_user=Depends(require_permission("reports"))):
    report_dir = settings.REPORT_OUTPUT_DIR
    if not os.path.exists(report_dir):
        return {"reports": []}
    files = sorted(os.listdir(report_dir), reverse=True)
    return {
        "reports": [
            {
                "filename": f,
                "url": f"/reports/{f}",
                "size_kb": round(os.path.getsize(os.path.join(report_dir, f)) / 1024, 1),
            }
            for f in files if f.endswith((".pdf", ".html"))
        ]
    }
