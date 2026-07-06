"""
SENTINEL-GRC — Threat Intelligence Tasks
Global SessionLocalSync. Canonical CVE IDs (no KEV- prefix duplication).
"""

import httpx
from datetime import datetime, timedelta
from typing import Optional
import structlog

from app.tasks.celery_app import celery_app
from app.core.config import settings

logger = structlog.get_logger()

MONITORED_ASSET_TYPES = [
    "postgresql", "nginx", "apache", "redis", "python",
    "openssl", "linux", "ubuntu", "docker", "kubernetes",
]


def _db():
    from app.db.database import SessionLocalSync
    return SessionLocalSync()


def _normalise_cve_id(raw: str) -> str:
    return raw.replace("KEV-", "").strip()


@celery_app.task(name="app.tasks.threat_intelligence.fetch_nvd_cves", bind=True)
def fetch_nvd_cves(self):
    pub_start = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

    params  = {"pubStartDate": pub_start, "pubEndDate": pub_end,
               "cvssV3Severity": "CRITICAL", "resultsPerPage": 50}
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}

    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                           params=params, headers=headers)
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])

        stored = 0
        for vw in vulns:
            v      = vw.get("cve", {})
            cve_id = _normalise_cve_id(v.get("id", ""))

            metrics    = v.get("metrics", {})
            cvss_score = cvss_vector = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(key):
                    d = metrics[key][0].get("cvssData", {})
                    cvss_score  = d.get("baseScore")
                    cvss_vector = d.get("vectorString")
                    break

            desc = next(
                (d["value"] for d in v.get("descriptions", []) if d.get("lang") == "en"),
                "No description"
            )

            products = []
            for cfg in v.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            p = parts[4].lower()
                            if p not in products:
                                products.append(p)

            affected = [a for a in MONITORED_ASSET_TYPES
                        if any(a in p for p in products)]

            _upsert_threat(
                source="nvd", canonical_id=cve_id,
                title=f"{cve_id} — {desc[:100]}", description=desc,
                cvss_score=cvss_score, cvss_vector=cvss_vector,
                severity="critical" if cvss_score and cvss_score >= 9.0 else "high",
                affected_products=products, assets_affected=affected,
                published_at=v.get("published"),
            )
            stored += 1

        impactful = sum(1 for vw in vulns
                        if any(a in str(vw) for a in MONITORED_ASSET_TYPES))
        if impactful > 0:
            from app.tasks.risk_recalculation import recalculate_all_risks
            recalculate_all_risks.delay()

        return {"fetched": len(vulns), "stored": stored, "impactful": impactful}
    except Exception as e:
        logger.error("NVD fetch failed", error=str(e))
        return {"error": str(e)}


@celery_app.task(name="app.tasks.threat_intelligence.fetch_cisa_kev", bind=True)
def fetch_cisa_kev(self):
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.get(settings.CISA_KEV_URL)
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])

        cutoff = datetime.utcnow() - timedelta(days=30)
        recent = [v for v in vulns
                  if datetime.strptime(v.get("dateAdded", "2000-01-01"), "%Y-%m-%d") > cutoff]

        for v in recent:
            cve_id  = _normalise_cve_id(v.get("cveID", ""))
            product = v.get("product", "").lower()
            vendor  = v.get("vendorProject", "").lower()
            affected = [a for a in MONITORED_ASSET_TYPES if a in product or a in vendor]
            due_str  = v.get("dueDate")
            due_date = datetime.strptime(due_str, "%Y-%m-%d") if due_str else None

            _upsert_threat(
                source="cisa_kev", canonical_id=cve_id,
                title=f"[ACTIVELY EXPLOITED] {cve_id} — {v.get('vulnerabilityName','')}",
                description=v.get("shortDescription", ""),
                cvss_score=None, cvss_vector=None, severity="critical",
                affected_products=[product], assets_affected=affected,
                published_at=v.get("dateAdded"),
                is_known_exploited=True, cisa_due_date=due_date,
            )

        return {"fetched": len(vulns), "recent": len(recent)}
    except Exception as e:
        logger.error("CISA KEV fetch failed", error=str(e))
        return {"error": str(e)}


def _upsert_threat(
    source: str, canonical_id: str, title: str, description: str,
    cvss_score: Optional[float], cvss_vector: Optional[str], severity: str,
    affected_products: list, assets_affected: list,
    published_at=None, is_known_exploited: bool = False, cisa_due_date=None,
):
    from app.models.threat import ThreatEvent
    from sqlalchemy import select

    session = _db()
    try:
        existing = session.execute(
            select(ThreatEvent).where(ThreatEvent.external_id == canonical_id)
        ).scalar_one_or_none()

        if existing:
            if is_known_exploited:
                existing.is_known_exploited = True
                existing.cisa_due_date      = cisa_due_date
                existing.source             = "nvd+cisa_kev"
            if assets_affected:
                base   = (cvss_score or existing.cvss_score or 7.0)
                delta  = base * len(assets_affected) * 50_000
                if is_known_exploited:
                    delta *= 3
                existing.risk_delta_gbp  = delta
                existing.assets_affected = assets_affected
            session.commit()
            return

        delta = 0.0
        if assets_affected:
            delta = (cvss_score or 7.0) * len(assets_affected) * 50_000
            if is_known_exploited:
                delta *= 3

        pub = None
        if published_at:
            try:
                pub = (datetime.fromisoformat(str(published_at).replace("Z",""))
                       if "T" in str(published_at)
                       else datetime.strptime(str(published_at), "%Y-%m-%d"))
            except Exception:
                pub = datetime.utcnow()

        session.add(ThreatEvent(
            source             = source,
            external_id        = canonical_id,
            title              = title[:499],
            description        = description,
            cvss_score         = cvss_score,
            cvss_vector        = cvss_vector,
            severity           = severity,
            affected_products  = affected_products,
            assets_affected    = assets_affected,
            risk_delta_gbp     = delta,
            is_known_exploited = is_known_exploited,
            cisa_due_date      = cisa_due_date,
            published_at       = pub,
            detected_at        = datetime.utcnow(),
        ))
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error("Failed to upsert threat", canonical_id=canonical_id, error=str(e))
    finally:
        session.close()
