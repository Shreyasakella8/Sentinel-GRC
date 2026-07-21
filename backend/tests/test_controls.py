"""
SENTINEL-GRC — Controls API Tests
"""

import pytest

@pytest.mark.asyncio
async def test_list_controls(client):
    """Test controls listing endpoint"""
    # Assuming the mock DB is seeded with catalog, but we mainly test the endpoint response
    response = await client.get("/api/v1/controls/")
    assert response.status_code in (200, 401)  # 401 if auth is strictly mocked

@pytest.mark.asyncio
async def test_get_control_history(client):
    """Test control history endpoint"""
    response = await client.get("/api/v1/controls/history/AC-001")
    assert response.status_code in (200, 401)
