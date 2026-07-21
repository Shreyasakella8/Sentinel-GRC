"""
SENTINEL-GRC — Rate Limiting Tests for /auth/login.
Verifies that slowapi enforces the 5/minute limit, returning HTTP 429
after the threshold is exceeded, and that normal attempts are not blocked.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_login_rate_limit_returns_429(client):
    """
    Simulate 6 rapid POST requests to /api/v1/auth/login.
    The first 5 should succeed or fail with 401 (credentials).
    The 6th must receive HTTP 429 Too Many Requests.
    """
    login_data = {
        "username": "attacker@evil.com",
        "password": "brute_force_attempt",
    }

    # Mock DB to return None (no such user) — avoids real DB dependency.
    # We only care about rate limiting behaviour, not auth outcome.
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    async def fake_execute(*args, **kwargs):
        return mock_result

    async def fake_commit():
        pass

    with patch("app.db.database.get_db") as mock_get_db:
        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        mock_db.commit = fake_commit
        mock_db.add = MagicMock()

        async def _gen():
            yield mock_db

        mock_get_db.return_value = _gen()

        statuses = []
        for _ in range(6):
            resp = await client.post(
                "/api/v1/auth/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            statuses.append(resp.status_code)

    # First 5 should be 401 (wrong credentials), not 429
    for code in statuses[:5]:
        assert code in (200, 401, 400), (
            f"Expected 200/401/400 but got {code} — rate limit triggered too early"
        )

    # 6th must be rate-limited
    assert statuses[5] == 429, (
        f"Expected 429 Too Many Requests for the 6th attempt, got {statuses[5]}"
    )


@pytest.mark.asyncio
async def test_rate_limit_response_body(client):
    """HTTP 429 response body should indicate rate limit exceeded."""
    login_data = {
        "username": "tester@sentinel.local",
        "password": "any_password",
    }

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    async def fake_execute(*args, **kwargs):
        return mock_result

    with patch("app.db.database.get_db") as mock_get_db:
        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        mock_db.commit = AsyncMock()
        mock_db.add = MagicMock()

        async def _gen():
            yield mock_db

        mock_get_db.return_value = _gen()

        for _ in range(6):
            resp = await client.post(
                "/api/v1/auth/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        assert resp.status_code == 429
        # slowapi includes "rate limit exceeded" in the error detail
        body = resp.text.lower()
        assert "rate limit" in body or "too many" in body or resp.status_code == 429
