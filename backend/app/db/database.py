"""
SENTINEL-GRC — Database Connection
Global engine + session factories declared once at module level.
Celery tasks import SessionLocalSync directly — no per-task engine creation,
no connection pool leaks under concurrent load.

Connection pool sizing formula:
  async pool_size  = (cpu_cores × 2) + effective_spindle_count  → default 20
  async max_overflow = pool_size × 2                              → default 40
  sync  pool_size  = min(4, num_celery_workers)                  → default 10
  sync  max_overflow = sync_pool_size                            → default 10

Monitor utilisation:
  SELECT count(*) FROM pg_stat_activity WHERE datname = 'sentinel_grc';
  Alert if count > pool_size + max_overflow - 2
"""

import os
from contextlib import contextmanager
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import settings

# ── Pool configuration (env-overridable) ──────────────────────────────────────
_ASYNC_POOL_SIZE    = int(os.getenv("DB_POOL_SIZE",       "20"))
_ASYNC_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW",    "40"))
_SYNC_POOL_SIZE     = int(os.getenv("SYNC_DB_POOL_SIZE",  "10"))
_SYNC_MAX_OVERFLOW  = int(os.getenv("SYNC_DB_MAX_OVERFLOW","10"))

# ── Async engine (FastAPI request handlers) ────────────────────────────────────
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=_ASYNC_POOL_SIZE,
    max_overflow=_ASYNC_MAX_OVERFLOW,
    pool_recycle=3600,   # Recycle stale connections every 1 h (avoids "server closed the connection" errors)
)

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Sync engine (Celery workers) ───────────────────────────────────────────────
# Declared ONCE at module level — all Celery tasks import this directly.
# Prevents a new connection pool being created for every task invocation.
sync_engine = create_engine(
    settings.SYNC_DATABASE_URL,
    pool_pre_ping=True,
    pool_size=_SYNC_POOL_SIZE,
    max_overflow=_SYNC_MAX_OVERFLOW,
    pool_recycle=3600,
)

SessionLocalSync = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


# ── FastAPI dependency ─────────────────────────────────────────────────────────
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


# ── Sync context manager for Celery tasks ─────────────────────────────────────
@contextmanager
def get_db_session():
    """
    Safe synchronous session context manager for Celery tasks.

    Usage:
        with get_db_session() as session:
            session.add(...)
            session.commit()

    Guarantees session.close() is called even if an exception occurs mid-loop,
    preventing connection leaks under concurrent task load.
    """
    session = SessionLocalSync()
    try:
        yield session
    finally:
        session.close()
