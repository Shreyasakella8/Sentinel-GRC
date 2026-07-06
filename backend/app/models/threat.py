"""SENTINEL-GRC — Threat Intelligence Models"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, JSON
from app.db.database import Base


class ThreatEvent(Base):
    """
    Live threat events ingested from NVD, CISA KEV, MITRE ATT&CK.
    TimescaleDB hypertable on detected_at.
    """
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(50), nullable=False, index=True)  # nvd / cisa_kev / mitre
    external_id = Column(String(100), unique=True, nullable=False, index=True)  # CVE-2024-XXXX

    title = Column(String(500))
    description = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    severity = Column(String(20))  # critical / high / medium / low

    # ATT&CK mapping
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))
    mitre_subtechnique = Column(String(100))

    affected_products = Column(JSON, default=list)  # ["postgresql", "nginx"]
    affected_versions = Column(Text)
    patch_available = Column(Boolean)
    patch_url = Column(Text)

    # CISA KEV fields
    is_known_exploited = Column(Boolean, default=False)
    cisa_due_date = Column(DateTime)

    # Impact on our environment
    assets_affected = Column(JSON, default=list)
    risk_delta_gbp = Column(Float, default=0)  # Change in financial exposure

    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    published_at = Column(DateTime)
    processed = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """
    Immutable system audit log for all user actions.
    TimescaleDB hypertable on created_at.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    user_email = Column(String(255))
    user_role = Column(String(50))

    action = Column(String(200), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(String(50))
    details = Column(JSON)

    ip_address = Column(String(50))
    user_agent = Column(String(500))
    success = Column(Boolean, default=True)
    error_message = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
