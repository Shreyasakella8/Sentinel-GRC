"""
SENTINEL-GRC — Database Connection
Global engine + session factories declared once at module level.
Celery tasks import SessionLocalSync directly — no per-task engine creation,
no connection pool leaks under concurrent load.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import settings

# ── Async engine (FastAPI request handlers) ────────────────────────────────
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Sync engine (Celery workers) ───────────────────────────────────────────
# Declared ONCE at module level — all Celery tasks import this directly.
# Prevents a new connection pool being created for every task invocation.
sync_engine = create_engine(
    settings.SYNC_DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

SessionLocalSync = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


# ── FastAPI dependency ─────────────────────────────────────────────────────
async def get_db():
    """
    Yield an async session for FastAPI request handlers.
    Write endpoints call await db.commit() explicitly.
    Only rolls back on unhandled exceptions.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
