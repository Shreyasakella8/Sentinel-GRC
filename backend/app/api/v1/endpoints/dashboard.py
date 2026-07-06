"""SENTINEL-GRC — Dashboard Endpoints"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timedelta

from app.core.security import get_current_user, require_permission
from app.db.database import get_db
from app.models.risk import Risk, RiskScore
from app.models.control import ControlResult
from app.models.threat import ThreatEvent
from app.models.governance import AuditFinding, Policy

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("dashboard")),
):
    """
    Main dashboard — financial risk exposure, compliance posture, top risks, trend data.
    Role-filtered: Board members see financial/exec view only.
    """

    # ── Compliance Posture ─────────────────────────────────────────────────────
    # Get latest result per control via subquery
    subq = (
        select(
            ControlResult.control_id,
            func.max(ControlResult.executed_at).label("latest_run"),
        )
        .group_by(ControlResult.control_id)
        .subquery()
    )

    latest_results = await db.execute(
        select(ControlResult).join(
            subq,
            (ControlResult.control_id == subq.c.control_id)
            & (ControlResult.executed_at == subq.c.latest_run),
        )
    )
    control_results = latest_results.scalars().all()

    total_controls = len(control_results)
    passed_controls = sum(1 for r in control_results if r.passed)
    compliance_score = round((passed_controls / total_controls * 100) if total_controls > 0 else 0)

    # ── Risk Summary ──────────────────────────────────────────────────────────
    open_risks = await db.execute(
        select(Risk).where(Risk.status.in_(["open", "under_treatment"]))
    )
    risks = open_risks.scalars().all()

    total_ale = sum(r.annualised_loss_expectancy_gbp or 0 for r in risks)
    critical_risks = sum(1 for r in risks if r.severity == "critical")
    high_risks = sum(1 for r in risks if r.severity == "high")
    escalated_risks = sum(1 for r in risks if r.escalated)
    board_approval_needed = sum(1 for r in risks if r.board_threshold_exceeded and not r.board_approved)

    # ── Top 5 Risks by ALE ────────────────────────────────────────────────────
    top_risks_result = await db.execute(
        select(Risk)
        .where(Risk.status.in_(["open", "under_treatment"]))
        .order_by(desc(Risk.annualised_loss_expectancy_gbp))
        .limit(5)
    )
    top_risks = top_risks_result.scalars().all()

    # ── Risk Trend (last 30 days) ─────────────────────────────────────────────
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    trend_result = await db.execute(
        select(
            func.date_trunc("day", RiskScore.recorded_at).label("day"),
            func.sum(RiskScore.ale_gbp).label("total_ale"),
        )
        .where(RiskScore.recorded_at >= thirty_days_ago)
        .group_by("day")
        .order_by("day")
    )
    trend_data = trend_result.all()

    # ── Threat Feed ───────────────────────────────────────────────────────────
    recent_threats_result = await db.execute(
        select(ThreatEvent)
        .order_by(desc(ThreatEvent.detected_at))
        .limit(5)
    )
    recent_threats = recent_threats_result.scalars().all()

    # ── Governance Metrics ────────────────────────────────────────────────────
    overdue_findings = await db.execute(
        select(func.count(AuditFinding.id)).where(
            AuditFinding.sla_breached == True,
            AuditFinding.status.in_(["open", "in_progress"]),
        )
    )
    overdue_findings_count = overdue_findings.scalar() or 0

    pending_policies = await db.execute(
        select(func.count(Policy.id)).where(
            Policy.status.in_(["draft", "legal_review", "ciso_approval"])
        )
    )
    pending_policies_count = pending_policies.scalar() or 0

    def fmt_gbp(amount):
        if amount is None:
            return "£0"
        if amount >= 1_000_000:
            return f"£{amount / 1_000_000:.1f}M"
        elif amount >= 1_000:
            return f"£{amount / 1_000:.0f}K"
        return f"£{int(amount):,}"

    return {
        "generated_at": datetime.utcnow().isoformat(),

        # Compliance
        "compliance": {
            "score": compliance_score,
            "total_controls": total_controls,
            "passed": passed_controls,
            "failed": total_controls - passed_controls,
            "last_sweep": (
                max((r.executed_at for r in control_results), default=None)
            ),
        },

        # Financial Risk
        "financial_risk": {
            "total_ale_gbp": round(total_ale, 2),
            "total_ale_formatted": fmt_gbp(total_ale),
            "open_risks": len(risks),
            "critical": critical_risks,
            "high": high_risks,
            "escalated": escalated_risks,
            "board_approval_needed": board_approval_needed,
        },

        # Top 5 Risks
        "top_risks": [
            {
                "risk_ref": r.risk_ref,
                "title": r.title,
                "severity": r.severity,
                "ale_formatted": fmt_gbp(r.annualised_loss_expectancy_gbp),
                "ale_gbp": r.annualised_loss_expectancy_gbp,
                "exploitation_prob": round((r.exploitation_probability_12m or 0) * 100, 1),
                "status": r.status,
                "escalated": r.escalated,
            }
            for r in top_risks
        ],

        # Risk Trend
        "risk_trend": [
            {
                "date": str(row.day)[:10] if row.day else "",
                "total_ale_gbp": round(float(row.total_ale or 0), 2),
            }
            for row in trend_data
        ],

        # Recent Threats
        "recent_threats": [
            {
                "external_id": t.external_id,
                "title": t.title,
                "severity": t.severity,
                "is_known_exploited": t.is_known_exploited,
                "assets_affected": t.assets_affected,
                "risk_delta_formatted": fmt_gbp(t.risk_delta_gbp),
                "detected_at": t.detected_at.isoformat() if t.detected_at else "",
            }
            for t in recent_threats
        ],

        # Governance
        "governance": {
            "overdue_findings": overdue_findings_count,
            "pending_policies": pending_policies_count,
        },

        # Control Health
        "control_health": [
            {
                "control_id": r.control_id,
                "control_name": r.control_name,
                "status": r.status,
                "passed": r.passed,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            }
            for r in control_results
        ],
    }
