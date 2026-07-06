"""SENTINEL-GRC — Compliance Framework & Control Catalog Models"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, JSON
from app.db.database import Base


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    version = Column(String(20))
    mandatory_sectors = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ControlCatalog(Base):
    __tablename__ = "control_catalog"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False)
    runner_module = Column(String(300))  # Python module path for automated runner

    # Framework mappings
    iso27001_clause = Column(String(50))
    nist_csf = Column(String(50))
    soc2_criteria = Column(String(50))
    cyber_essentials = Column(String(50))
    uk_gdpr_article = Column(String(50))

    severity = Column(String(20), default="medium")  # critical/high/medium/low
    frequency_hours = Column(Integer, default=24)
    fine_exposure_gbp = Column(Float, default=0)  # Maximum regulatory fine

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
