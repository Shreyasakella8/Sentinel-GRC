"""
SENTINEL-GRC — Slack Notifier Unit Tests.
Verifies alert payload construction (Block Kit format, colour codes,
GBP formatting) and graceful degradation when webhook URL is not set.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.slack_notifier import (
    _build_payload,
    send_risk_alert_async,
    send_risk_alert_sync,
    _SEVERITY_COLOURS,
)


# ─── Payload construction ──────────────────────────────────────────────────────

class TestBuildPayload:

    def test_critical_colour(self):
        payload = _build_payload(
            event_type="risk_created",
            risk_ref="RISK-0001",
            title="Critical DB Exposure",
            severity="critical",
            ale_gbp=1_200_000.0,
            detail="Test detail",
        )
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#E01E5A"

    def test_gbp_formatting_millions(self):
        payload = _build_payload(
            event_type="risk_created",
            risk_ref="RISK-0002",
            title="High ALE Risk",
            severity="critical",
            ale_gbp=2_500_000.0,
            detail="Test",
        )
        fallback = payload["attachments"][0]["fallback"]
        assert "£2.5M" in fallback

    def test_gbp_formatting_thousands(self):
        payload = _build_payload(
            event_type="board_threshold",
            risk_ref="RISK-0003",
            title="Medium Risk",
            severity="high",
            ale_gbp=750_000.0,
            detail="Test",
        )
        fallback = payload["attachments"][0]["fallback"]
        assert "£750K" in fallback

    def test_payload_contains_risk_ref(self):
        payload = _build_payload(
            event_type="risk_escalated",
            risk_ref="RISK-9999",
            title="Any Risk",
            severity="high",
            ale_gbp=600_000.0,
            detail="Test",
        )
        blocks = payload["attachments"][0]["blocks"]
        # Find the section block with fields
        fields_block = next(b for b in blocks if b["type"] == "section" and "fields" in b)
        field_texts = [f["text"] for f in fields_block["fields"]]
        assert any("RISK-9999" in t for t in field_texts)

    def test_channel_is_injected(self):
        payload = _build_payload(
            event_type="control_failure",
            risk_ref="RISK-0004",
            title="Control Failure",
            severity="critical",
            ale_gbp=100_000.0,
            detail="Test",
            channel="#incidents",
        )
        assert payload.get("channel") == "#incidents"

    def test_no_channel_when_not_provided(self):
        payload = _build_payload(
            event_type="control_failure",
            risk_ref="RISK-0005",
            title="Control Failure",
            severity="critical",
            ale_gbp=100_000.0,
            detail="Test",
        )
        assert "channel" not in payload


# ─── Graceful degradation ──────────────────────────────────────────────────────

class TestGracefulDegradation:

    @pytest.mark.asyncio
    async def test_async_skips_when_no_webhook(self):
        """send_risk_alert_async should not raise when SLACK_WEBHOOK_URL is empty."""
        with patch("app.services.slack_notifier.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = None
            mock_settings.SLACK_ALERT_CHANNEL = "#security-alerts"
            # Should complete without raising
            await send_risk_alert_async(
                event_type="risk_created",
                risk_ref="RISK-0001",
                title="Test",
                severity="critical",
                ale_gbp=1_000_000.0,
            )

    def test_sync_skips_when_no_webhook(self):
        """send_risk_alert_sync should not raise when SLACK_WEBHOOK_URL is empty."""
        with patch("app.services.slack_notifier.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = None
            mock_settings.SLACK_ALERT_CHANNEL = "#security-alerts"
            send_risk_alert_sync(
                event_type="risk_escalated",
                risk_ref="RISK-0001",
                title="Test",
                severity="high",
                ale_gbp=600_000.0,
            )


# ─── Successful delivery ──────────────────────────────────────────────────────

class TestSlackDelivery:

    @pytest.mark.asyncio
    async def test_async_posts_to_webhook(self):
        """send_risk_alert_async should POST to the configured webhook URL."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.slack_notifier.settings") as mock_settings, \
             patch("httpx.AsyncClient") as mock_http_cls:

            mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/test/webhook"
            mock_settings.SLACK_ALERT_CHANNEL = "#security-alerts"

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_http_cls.return_value = mock_client

            await send_risk_alert_async(
                event_type="risk_created",
                risk_ref="RISK-ALERT-001",
                title="Critical Cloud Misconfiguration",
                severity="critical",
                ale_gbp=2_000_000.0,
                detail="IAM roles misconfigured allowing public read.",
            )

            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            # First arg is the URL
            assert call_kwargs[0][0] == "https://hooks.slack.com/test/webhook"
