"""
SENTINEL-GRC — Module 5: Three-Tier Report Engine
Generates Board, Auditor, and Technical reports from the same data.
Uses WeasyPrint for professional PDF output with org letterhead.
"""

import os
import json
from datetime import datetime
from typing import Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
import structlog

from app.core.config import settings

logger = structlog.get_logger()


REPORT_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "report_templates")


def _get_jinja_env():
    return Environment(
        loader=FileSystemLoader(REPORT_TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )


def _format_gbp(amount: Optional[float]) -> str:
    if amount is None:
        return "£0"
    if amount >= 1_000_000:
        return f"£{amount / 1_000_000:.1f}M"
    elif amount >= 1_000:
        return f"£{amount / 1_000:.0f}K"
    return f"£{int(amount):,}"


def _get_compliance_data(session) -> dict:
    """Aggregate compliance posture across all frameworks."""
    from app.models.control import ControlResult
    from sqlalchemy import select, func, desc
    from sqlalchemy.orm import Session

    # Get latest result for each control
    subquery = (
        select(
            ControlResult.control_id,
            func.max(ControlResult.executed_at).label("latest")
        )
        .group_by(ControlResult.control_id)
        .subquery()
    )

    latest_results = session.execute(
        select(ControlResult).join(
            subquery,
            (ControlResult.control_id == subquery.c.control_id) &
            (ControlResult.executed_at == subquery.c.latest)
        )
    ).scalars().all()

    total = len(latest_results)
    passed = sum(1 for r in latest_results if r.passed)
    compliance_score = round((passed / total * 100) if total > 0 else 0)

    return {
        "total_controls": total,
        "passed": passed,
        "failed": total - passed,
        "compliance_score": compliance_score,
        "results": [
            {
                "control_id": r.control_id,
                "control_name": r.control_name,
                "status": r.status,
                "passed": r.passed,
                "finding": r.finding,
                "iso27001": "",
                "nist_csf": "",
                "soc2": "",
                "executed_at": r.executed_at.strftime("%Y-%m-%d %H:%M UTC") if r.executed_at else "Never",
            }
            for r in latest_results
        ],
    }


def _get_risk_summary(session) -> dict:
    """Get risk register summary for reports."""
    from app.models.risk import Risk
    from sqlalchemy import select, func

    risks = session.execute(
        select(Risk).where(Risk.status.in_(["open", "under_treatment"]))
        .order_by(Risk.annualised_loss_expectancy_gbp.desc())
    ).scalars().all()

    total_ale = sum(r.annualised_loss_expectancy_gbp or 0 for r in risks)
    critical = [r for r in risks if r.severity == "critical"]
    high = [r for r in risks if r.severity == "high"]

    return {
        "total_open_risks": len(risks),
        "critical_count": len(critical),
        "high_count": len(high),
        "total_ale_gbp": total_ale,
        "total_ale_formatted": _format_gbp(total_ale),
        "top_5_risks": [
            {
                "risk_ref": r.risk_ref,
                "title": r.title,
                "severity": r.severity,
                "ale_gbp": r.annualised_loss_expectancy_gbp,
                "ale_formatted": _format_gbp(r.annualised_loss_expectancy_gbp),
                "exploitation_prob": f"{round((r.exploitation_probability_12m or 0) * 100)}%",
                "status": r.status,
                "treatment": r.treatment or "Pending",
            }
            for r in risks[:5]
        ],
        "all_risks": [
            {
                "risk_ref": r.risk_ref,
                "title": r.title,
                "severity": r.severity,
                "ale_gbp": _format_gbp(r.annualised_loss_expectancy_gbp),
                "ale_90th": _format_gbp(r.ale_90th_percentile_gbp),
                "exploitation_prob": f"{round((r.exploitation_probability_12m or 0) * 100)}%",
                "tef": f"{r.threat_event_frequency:.1f}" if r.threat_event_frequency is not None else "—",
                "vuln_pct": f"{round((r.vulnerability_probability or 0) * 100)}%" if r.vulnerability_probability is not None else "—",
                "status": r.status,
                "treatment": r.treatment or "Pending",
                "frameworks": ", ".join(r.frameworks_impacted or []),
                "source": r.source,
                "created_at": r.created_at.strftime("%Y-%m-%d") if r.created_at else "",
            }
            for r in risks
        ],
        "escalated_count": sum(1 for r in risks if r.escalated),
        "board_approval_needed": sum(1 for r in risks if r.board_threshold_exceeded and not r.board_approved),
    }


def generate_board_report(session, output_path: Optional[str] = None) -> str:
    """
    Board Report: Executive summary with financial risk in GBP.
    Non-technical. Clean, visual. Suitable for C-suite and board meetings.
    """
    try:
        from weasyprint import HTML, CSS

        compliance = _get_compliance_data(session)
        risk_summary = _get_risk_summary(session)

        context = {
            "report_type": "Board Executive Report",
            "report_date": datetime.utcnow().strftime("%d %B %Y"),
            "org_name": settings.ORG_NAME,
            "compliance": compliance,
            "risk": risk_summary,
            "generated_by": "SENTINEL-GRC Automated Reporting Engine",
        }

        html_content = _render_template("board_report.html", context)

        filename = f"board_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = output_path or os.path.join(settings.REPORT_OUTPUT_DIR, filename)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        HTML(string=html_content).write_pdf(output_path)

        logger.info("Board report generated", path=output_path)
        return output_path

    except Exception as e:
        logger.error("Board report generation failed", error=str(e))
        # Fallback: save HTML
        filename = f"board_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html_content if 'html_content' in locals() else f"<p>Error: {e}</p>")
        return output_path


def generate_auditor_report(session, output_path: Optional[str] = None) -> str:
    """
    Auditor Report: Full control evidence, framework mapping, non-conformities.
    Formatted to ISO 27001 audit standards.
    """
    try:
        from weasyprint import HTML

        compliance = _get_compliance_data(session)
        risk_summary = _get_risk_summary(session)

        # Get evidence entries
        from app.models.evidence import EvidenceEntry
        from sqlalchemy import select
        evidence_entries = session.execute(
            select(EvidenceEntry).order_by(EvidenceEntry.collected_at.desc()).limit(100)
        ).scalars().all()

        context = {
            "report_type": "ISO 27001 Audit Report",
            "report_date": datetime.utcnow().strftime("%d %B %Y"),
            "org_name": settings.ORG_NAME,
            "compliance": compliance,
            "risk": risk_summary,
            "evidence": [
                {
                    "entry_ref": e.entry_ref,
                    "control_id": e.control_id,
                    "evidence_type": e.evidence_type,
                    "summary": e.summary,
                    "content_hash": e.content_hash,
                    "hmac_signature": e.hmac_signature[:16] + "..." if e.hmac_signature else "",
                    "chain_valid": e.chain_valid,
                    "frameworks": e.frameworks_covered,
                    "collected_at": e.collected_at.strftime("%Y-%m-%d %H:%M UTC") if e.collected_at else "",
                }
                for e in evidence_entries
            ],
            "generated_by": "SENTINEL-GRC Automated Reporting Engine",
        }

        html_content = _render_template("auditor_report.html", context)

        filename = f"auditor_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = output_path or os.path.join(settings.REPORT_OUTPUT_DIR, filename)
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)

        HTML(string=html_content).write_pdf(output_path)
        logger.info("Auditor report generated", path=output_path)
        return output_path

    except Exception as e:
        logger.error("Auditor report generation failed", error=str(e))
        filename = f"auditor_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html_content if 'html_content' in locals() else f"<p>Error: {e}</p>")
        return output_path


def generate_technical_report(session, output_path: Optional[str] = None) -> str:
    """
    Technical Report: Raw findings, control runner output, remediation steps with code.
    For the security engineering team.
    """
    try:
        from weasyprint import HTML

        compliance = _get_compliance_data(session)
        risk_summary = _get_risk_summary(session)

        # Get all control results with raw output
        from app.models.control import ControlResult
        from sqlalchemy import select, desc
        results = session.execute(
            select(ControlResult)
            .order_by(desc(ControlResult.executed_at))
            .limit(200)
        ).scalars().all()

        context = {
            "report_type": "Technical Security Report",
            "report_date": datetime.utcnow().strftime("%d %B %Y"),
            "org_name": settings.ORG_NAME,
            "compliance": compliance,
            "risk": risk_summary,
            "control_results": [
                {
                    "control_id": r.control_id,
                    "control_name": r.control_name,
                    "status": r.status,
                    "passed": r.passed,
                    "finding": r.finding,
                    "raw_output": r.raw_output,
                    "risk_contribution_gbp": _format_gbp(r.risk_contribution_gbp),
                    "evidence_hash": r.evidence_hash,
                    "executed_at": r.executed_at.strftime("%Y-%m-%d %H:%M UTC") if r.executed_at else "",
                }
                for r in results
            ],
            "generated_by": "SENTINEL-GRC Automated Reporting Engine",
        }

        html_content = _render_template("technical_report.html", context)

        filename = f"technical_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = output_path or os.path.join(settings.REPORT_OUTPUT_DIR, filename)
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)

        HTML(string=html_content).write_pdf(output_path)
        logger.info("Technical report generated", path=output_path)
        return output_path

    except Exception as e:
        logger.error("Technical report generation failed", error=str(e))
        filename = f"technical_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(settings.REPORT_OUTPUT_DIR, filename)
        os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html_content if 'html_content' in locals() else f"<p>Error: {e}</p>")
        return output_path


def _render_template(template_name: str, context: dict) -> str:
    """Render a Jinja2 HTML template."""
    try:
        env = _get_jinja_env()
        template = env.get_template(template_name)
        return template.render(**context)
    except Exception as e:
        logger.error("Template render failed", template=template_name, error=str(e))
        # Fallback inline HTML
        return _fallback_html(context)


def _fallback_html(context: dict) -> str:
    """Simple fallback HTML if template files are missing."""
    risk = context.get("risk", {})
    compliance = context.get("compliance", {})

    top_risks_rows = ""
    for r in risk.get('top_5_risks', []):
        top_risks_rows += f"""<tr>
            <td>{r['risk_ref']}</td>
            <td>{r['title'][:80]}</td>
            <td class="{r['severity']}">{r['severity'].upper()}</td>
            <td>{r['ale_formatted']}</td>
            <td>{r['exploitation_prob']}</td>
            <td>{r['treatment']}</td>
        </tr>"""

    control_results_rows = ""
    for r in compliance.get('results', []):
        control_results_rows += f"""<tr>
            <td>{r['control_id']}</td>
            <td>{r['control_name']}</td>
            <td class="{'pass' if r['passed'] else 'fail'}">{r['status'].upper()}</td>
            <td>{(r['finding'] or '')[:120]}</td>
            <td>{r['executed_at']}</td>
        </tr>"""

    return f"""
    <!DOCTYPE html><html><head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; color: #1a1a2e; }}
        h1 {{ color: #e94560; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        .metric {{ display: inline-block; background: #16213e; color: white;
                   padding: 20px; margin: 10px; border-radius: 8px; min-width: 150px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #e94560; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #16213e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #ddd; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .critical {{ color: #e94560; font-weight: bold; }}
        .high {{ color: #ff6b35; font-weight: bold; }}
        .pass {{ color: #28a745; }}
        .fail {{ color: #e94560; }}
    </style>
    </head><body>
    <h1>SENTINEL-GRC — {context.get('report_type', 'Report')}</h1>
    <p><strong>Organisation:</strong> {context.get('org_name', 'N/A')} |
       <strong>Date:</strong> {context.get('report_date', 'N/A')} |
       <strong>Generated by:</strong> {context.get('generated_by', 'SENTINEL-GRC')}</p>

    <h2>Compliance Posture</h2>
    <div class="metric">
        <div class="metric-value">{compliance.get('compliance_score', 0)}%</div>
        <div>Compliance Score</div>
    </div>
    <div class="metric">
        <div class="metric-value">{compliance.get('passed', 0)}/{compliance.get('total_controls', 0)}</div>
        <div>Controls Passing</div>
    </div>

    <h2>Risk Exposure</h2>
    <div class="metric">
        <div class="metric-value">{risk.get('total_ale_formatted', '£0')}</div>
        <div>Total Annual Loss Exposure</div>
    </div>
    <div class="metric">
        <div class="metric-value">{risk.get('critical_count', 0)}</div>
        <div>Critical Risks</div>
    </div>
    <div class="metric">
        <div class="metric-value">{risk.get('total_open_risks', 0)}</div>
        <div>Open Risks</div>
    </div>

    <h2>Top Risks</h2>
    <table>
        <tr><th>Ref</th><th>Risk</th><th>Severity</th><th>ALE</th><th>Exploit Prob.</th><th>Treatment</th></tr>
        {top_risks_rows}
    </table>

    <h2>Control Results</h2>
    <table>
        <tr><th>Control ID</th><th>Name</th><th>Status</th><th>Finding</th><th>Last Run</th></tr>
        {control_results_rows}
    </table>
    </body></html>
    """
