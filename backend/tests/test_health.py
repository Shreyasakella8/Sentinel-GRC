"""
SENTINEL-GRC — Health endpoint tests.
Verifies the /health endpoint is reachable and returns expected fields.
"""

import pytest


@pytest.mark.asyncio
async def test_health_returns_200(client):
    """GET /health should return 200 OK."""
    response = await client.get("/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_payload(client):
    """GET /health should return status=operational and a service name."""
    response = await client.get("/health")
    data = response.json()
    assert data["status"] == "operational"
    assert data["service"] == "SENTINEL-GRC"
    assert "version" in data


@pytest.mark.asyncio
async def test_openapi_docs_accessible(client):
    """GET /api/docs should be reachable (Swagger UI)."""
    response = await client.get("/api/docs")
    assert response.status_code == 200
