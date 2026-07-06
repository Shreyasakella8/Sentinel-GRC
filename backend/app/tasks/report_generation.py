"""
SENTINEL-GRC — Report Generation Task
Celery task wrapper for async PDF report generation.
"""

from app.tasks.celery_app import celery_app
from app.core.config import settings
import structlog

logger = structlog.get_logger()


def _get_sync_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(settings.SYNC_DATABASE_URL)
    return sessionmaker(bind=engine)()


@celery_app.task(name="app.tasks.report_generation.generate_board_report_task", bind=True)
def generate_board_report_task(self):
    """Generate board report asynchronously."""
    session = _get_sync_session()
    try:
        from app.services.report_generator import generate_board_report
        path = generate_board_report(session)
        logger.info("Board report task complete", path=path)
        return {"status": "success", "path": path}
    except Exception as e:
        logger.error("Board report task failed", error=str(e))
        return {"status": "error", "error": str(e)}
    finally:
        session.close()


@celery_app.task(name="app.tasks.report_generation.generate_auditor_report_task", bind=True)
def generate_auditor_report_task(self):
    """Generate auditor report asynchronously."""
    session = _get_sync_session()
    try:
        from app.services.report_generator import generate_auditor_report
        path = generate_auditor_report(session)
        return {"status": "success", "path": path}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        session.close()


@celery_app.task(name="app.tasks.report_generation.generate_technical_report_task", bind=True)
def generate_technical_report_task(self):
    """Generate technical report asynchronously."""
    session = _get_sync_session()
    try:
        from app.services.report_generator import generate_technical_report
        path = generate_technical_report(session)
        return {"status": "success", "path": path}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        session.close()
