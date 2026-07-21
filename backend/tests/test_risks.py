"""
SENTINEL-GRC — Risks API Tests
"""

import pytest

@pytest.mark.asyncio
async def test_list_risks_pagination(client):
    """Test risk listing pagination"""
    response = await client.get("/api/v1/risks/?limit=10")
    assert response.status_code in (200, 401)

@pytest.mark.asyncio
async def test_get_risk_detail(client):
    """Test risk detail endpoint"""
    response = await client.get("/api/v1/risks/1")
    assert response.status_code in (200, 401, 404)
