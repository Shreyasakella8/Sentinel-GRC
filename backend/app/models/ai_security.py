"""
SENTINEL-GRC — AI Security Models
Stores every guardrail scan, AI risk assessment, and AI policy.
TimescaleDB hypertable on scanned_at for time-series queries.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Text, Float, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.db.database import Base


class AIGuardrailLog(Base):
    """Every scan that passes through the guardrail pipeline."""
    __tablename__ = "ai_guardrail_logs"

    id             = Column(Integer, primary_key=True, index=True)
    session_id     = Column(String(64), index=True)      # group multi-turn conversations
    context        = Column(String(100))                  # user_input / model_output / api_call
    input_hash     = Column(String(64), index=True)       # SHA-256 of original text
    input_preview  = Column(String(500))                  # first 500 chars (redacted)

    # Pipeline results
    allowed        = Column(Boolean, nullable=False)
    classification = Column(String(50))                   # clean/suspicious/injection/exfil/jailbreak/ai_threat
    risk_score     = Column(Float)                        # 0.0 – 1.0
    finding_count  = Column(Integer, default=0)
    findings       = Column(JSON, default=list)           # full finding list
    redacted       = Column(Boolean, default=False)
    processing_ms  = Column(Integer)

    # Attribution
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_email     = Column(String(255))
    ip_address     = Column(String(50))

    scanned_at     = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", foreign_keys=[user_id])


class AIRiskAssessment(Base):
    """
    NIST AI RMF-aligned risk assessment for a deployed AI system.
    Covers: Govern, Map, Measure, Manage quadrants.
    """
    __tablename__ = "ai_risk_assessments"

    id                = Column(Integer, primary_key=True, index=True)
    assessment_ref    = Column(String(30), unique=True, nullable=False, index=True)

    # System under assessment
    ai_system_name    = Column(String(200), nullable=False)
    ai_system_version = Column(String(50))
    ai_system_type    = Column(String(100))   # llm / cv / recommendation / nlp / other
    deployment_env    = Column(String(50))    # production / staging / research
    vendor            = Column(String(200))

    # NIST AI RMF — GOVERN
    gov_policies_defined     = Column(Float, default=0.0)   # 0.0 – 1.0 slider
    gov_roles_assigned       = Column(Float, default=0.0)
    gov_accountability       = Column(Float, default=0.0)
    gov_third_party_oversight = Column(Float, default=0.0)

    # NIST AI RMF — MAP
    map_context_established  = Column(Float, default=0.0)
    map_impact_assessment    = Column(Float, default=0.0)
    map_bias_identified      = Column(Float, default=0.0)
    map_data_lineage         = Column(Float, default=0.0)

    # NIST AI RMF — MEASURE
    msr_accuracy             = Column(Float, default=0.0)
    msr_robustness           = Column(Float, default=0.0)
    msr_fairness             = Column(Float, default=0.0)
    msr_explainability       = Column(Float, default=0.0)
    msr_privacy              = Column(Float, default=0.0)
    msr_security             = Column(Float, default=0.0)
    msr_adversarial_testing  = Column(Float, default=0.0)

    # NIST AI RMF — MANAGE
    mng_incident_response    = Column(Float, default=0.0)
    mng_monitoring           = Column(Float, default=0.0)
    mng_decommission_plan    = Column(Float, default=0.0)
    mng_human_oversight      = Column(Float, default=0.0)

    # Composite scores (calculated)
    govern_score    = Column(Float)
    map_score       = Column(Float)
    measure_score   = Column(Float)
    manage_score    = Column(Float)
    composite_score = Column(Float)           # weighted average
    risk_tier       = Column(String(20))      # critical / high / medium / low

    # Linked risk record
    risk_id         = Column(Integer, ForeignKey("risks.id"), nullable=True)

    # Meta
    assessed_by_id  = Column(Integer, ForeignKey("users.id"))
    status          = Column(String(30), default="draft")  # draft / approved / archived
    notes           = Column(Text)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    assessed_by = relationship("User", foreign_keys=[assessed_by_id])


class AISecurityPolicy(Base):
    """
    Organisation AI usage and security policies.
    Separate from the GRC policy lifecycle — AI policies have
    their own approval chain under the CISO.
    """
    __tablename__ = "ai_security_policies"

    id          = Column(Integer, primary_key=True, index=True)
    policy_ref  = Column(String(30), unique=True, nullable=False, index=True)
    title       = Column(String(300), nullable=False)
    category    = Column(String(100))   # acceptable_use / data_handling / vendor_risk / incident
    description = Column(Text)
    content     = Column(Text)
    status      = Column(String(30), default="draft")  # draft / active / retired
    version     = Column(String(20), default="1.0")

    author_id   = Column(Integer, ForeignKey("users.id"))
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    author   = relationship("User", foreign_keys=[author_id])
    approver = relationship("User", foreign_keys=[approved_by])
