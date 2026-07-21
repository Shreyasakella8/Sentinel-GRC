"""
SENTINEL-GRC — Slack Notification Service
Posts rich Block Kit alert cards for critical risk events.

Supports both async (FastAPI route context) and sync (Celery task context) posting.
If SLACK_WEBHOOK_URL is not configured, alerts degrade gracefully to a log warning.
"""

from __future__ import annotations

import structlog
from typing import Optional

import httpx

from app.core.config import settings

logger = structlog.get_logger()

# Colour mapping for severity levels (Slack attachment colour field)
_SEVERITY_COLOURS = {
    "critical": "#E01E5A",   # vivid red
    "high":     "#FF6B35",   # orange-red
    "medium":   "#F7B731",   # amber
    "low":      "#20BF6B",   # green
}

# Human-readable event title mapping
_EVENT_TITLES = {
    "risk_created":       "🚨 Critical Risk Created",
    "risk_escalated":     "⬆️  Risk Escalated",
    "board_threshold":    "🏛️  Board Approval Required",
    "control_failure":    "⚠️  Critical Control Failure",
}


def _build_payload(
    event_type: str,
    risk_ref: str,
    title: str,
    severity: str,
    ale_gbp: float,
    detail: str,
    channel: Optional[str] = None,
) -> dict:
    """Assemble a Slack Block Kit payload with a coloured attachment card."""

    def _fmt_gbp(v: float) -> str:
        if v >= 1_000_000:
            return f"£{v / 1_000_000:.1f}M"
        if v >= 1_000:
            return f"£{v / 1_000:.0f}K"
        return f"£{int(v):,}"

    colour  = _SEVERITY_COLOURS.get(severity.lower(), "#E01E5A")
    ev_title = _EVENT_TITLES.get(event_type, "⚠️ Sentinel GRC Alert")

    payload: dict = {
        "username":   "SENTINEL-GRC",
        "icon_emoji": ":shield:",
        "attachments": [
            {
                "color":    colour,
                "fallback": f"{ev_title} — {risk_ref}: {title} | ALE {_fmt_gbp(ale_gbp)}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": ev_title, "emoji": True},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Risk Reference*\n`{risk_ref}`"},
                            {"type": "mrkdwn", "text": f"*Severity*\n{severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*ALE (Expected Annual Loss)*\n{_fmt_gbp(ale_gbp)}"},
                            {"type": "mrkdwn", "text": f"*Title*\n{title}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Details*\n{detail}"},
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Posted by *SENTINEL-GRC Continuous Controls Monitoring*",
                            }
                        ],
                    },
                ],
            }
        ],
    }

    if channel:
        payload["channel"] = channel

    return payload


# ── Async variant (FastAPI / asyncio context) ─────────────────────────────────

async def send_risk_alert_async(
    event_type: str,
    risk_ref:   str,
    title:      str,
    severity:   str,
    ale_gbp:    float,
    detail:     str = "",
) -> None:
    """
    Async-safe Slack notification. Call from FastAPI route handlers.
    Silently skips if SLACK_WEBHOOK_URL is not configured.
    """
    webhook_url = settings.SLACK_WEBHOOK_URL
    if not webhook_url:
        logger.warning(
            "Slack alert skipped — SLACK_WEBHOOK_URL not configured",
            event_type=event_type,
            risk_ref=risk_ref,
        )
        return

    payload = _build_payload(
        event_type=event_type,
        risk_ref=risk_ref,
        title=title,
        severity=severity,
        ale_gbp=ale_gbp,
        detail=detail,
        channel=settings.SLACK_ALERT_CHANNEL or None,
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            logger.info(
                "Slack alert sent",
                event_type=event_type,
                risk_ref=risk_ref,
                status_code=resp.status_code,
            )
    except Exception as exc:
        # Never propagate — Slack failure must not break core operations
        logger.error(
            "Slack alert failed",
            event_type=event_type,
            risk_ref=risk_ref,
            error=str(exc),
        )


# ── Sync variant (Celery task context) ───────────────────────────────────────

def send_risk_alert_sync(
    event_type: str,
    risk_ref:   str,
    title:      str,
    severity:   str,
    ale_gbp:    float,
    detail:     str = "",
) -> None:
    """
    Synchronous Slack notification. Call from Celery tasks.
    Silently skips if SLACK_WEBHOOK_URL is not configured.
    """
    webhook_url = settings.SLACK_WEBHOOK_URL
    if not webhook_url:
        logger.warning(
            "Slack alert skipped — SLACK_WEBHOOK_URL not configured",
            event_type=event_type,
            risk_ref=risk_ref,
        )
        return

    payload = _build_payload(
        event_type=event_type,
        risk_ref=risk_ref,
        title=title,
        severity=severity,
        ale_gbp=ale_gbp,
        detail=detail,
        channel=settings.SLACK_ALERT_CHANNEL or None,
    )

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(webhook_url, json=payload)
            resp.raise_for_status()
            logger.info(
                "Slack alert sent (sync)",
                event_type=event_type,
                risk_ref=risk_ref,
                status_code=resp.status_code,
            )
    except Exception as exc:
        logger.error(
            "Slack alert failed (sync)",
            event_type=event_type,
            risk_ref=risk_ref,
            error=str(exc),
        )
