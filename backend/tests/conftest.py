"""
SENTINEL-GRC — Pytest configuration and shared fixtures.
Uses httpx.AsyncClient with ASGITransport for in-process testing without
a running server or real database connections.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def client():
    """
    Async test client for the FastAPI app.
    Patches database and Redis dependencies so tests run without
    external services.
    """
    # Patch settings so no real .env is needed in CI
    env_overrides = {
        "DATABASE_URL": "postgresql+asyncpg://sentinel:sentinel_secret@localhost:5432/sentinel_grc_test",
        "SYNC_DATABASE_URL": "postgresql://sentinel:sentinel_secret@localhost:5432/sentinel_grc_test",
        "REDIS_URL": "redis://localhost:6379/0",
        "CELERY_BROKER_URL": "redis://localhost:6379/0",
        "CELERY_RESULT_BACKEND": "redis://localhost:6379/1",
        "SECRET_KEY": "ci_test_secret_key_32chars_minimum",
        "EVIDENCE_HMAC_KEY": "ci_test_hmac_key_32chars_minimum_x",
        "MINIO_ENDPOINT": "localhost:9000",
        "MINIO_ACCESS_KEY": "minioadmin",
        "MINIO_SECRET_KEY": "minioadmin",
        "MINIO_SECURE": "false",
        "SLACK_WEBHOOK_URL": "",
    }

    with patch.dict("os.environ", env_overrides, clear=False):
        from app.main import app
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as ac:
            yield ac


@pytest.fixture
def mock_db():
    """In-memory SQLite for fast tests"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


@pytest.fixture
def mock_celery():
    """Always-eager Celery for deterministic tests"""
    from celery import current_app
    current_app.conf.update(task_always_eager=True)
    return current_app


@pytest.fixture
def mock_minio():
    """Fake MinIO responses"""
    with patch('app.services.evidence_vault.Minio') as m:
        m.return_value.put_object = AsyncMock(return_value=None)
        m.return_value.get_object = AsyncMock(return_value=None)
        yield m
