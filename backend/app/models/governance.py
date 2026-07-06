"""SENTINEL-GRC — Governance Workflow Models
Policy lifecycle, audit management, and governance actions.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base


class Policy(Base):
    """Policy lifecycle management. States enforce governance workflow."""
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    policy_ref = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # information_security / data_protection / access_control

    # Lifecycle state machine:
    # draft → legal_review → ciso_approval → published → scheduled_review → retired
    status = Column(String(50), default="draft", nullable=False)
    version = Column(String(20), default="1.0")

    content = Column(Text)
    framework_references = Column(JSON, default=list)

    # Ownership
    author_id = Column(Integer, ForeignKey("users.id"))
    reviewer_id = Column(Integer, ForeignKey("users.id"))
    approver_id = Column(Integer, ForeignKey("users.id"))

    # Dates
    review_due_date = Column(DateTime)
    approved_at = Column(DateTime)
    published_at = Column(DateTime)
    next_review_date = Column(DateTime)
    retired_at = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    author = relationship("User", foreign_keys=[author_id])
    approver = relationship("User", foreign_keys=[approver_id])
    history = relationship("PolicyHistory", back_populates="policy")


class PolicyHistory(Base):
    """Immutable audit trail of every policy state change."""
    __tablename__ = "policy_history"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False, index=True)
    from_status = Column(String(50))
    to_status = Column(String(50))
    changed_by_id = Column(Integer, ForeignKey("users.id"))
    comment = Column(Text)
    changed_at = Column(DateTime, default=datetime.utcnow)

    policy = relationship("Policy", back_populates="history")
    changed_by = relationship("User", foreign_keys=[changed_by_id])


class AuditPlan(Base):
    """Scheduled audit with assigned auditors."""
    __tablename__ = "audit_plans"

    id = Column(Integer, primary_key=True, index=True)
    audit_ref = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    scope = Column(Text)
    framework = Column(String(50))  # ISO27001 / SOC2 / NIST_CSF etc.
    audit_type = Column(String(50))  # internal / external / surveillance

    status = Column(String(50), default="planned")  # planned / in_progress / complete / cancelled

    lead_auditor_id = Column(Integer, ForeignKey("users.id"))
    scheduled_start = Column(DateTime)
    scheduled_end = Column(DateTime)
    actual_start = Column(DateTime)
    actual_end = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)

    lead_auditor = relationship("User", foreign_keys=[lead_auditor_id])
    findings = relationship("AuditFinding", back_populates="audit")


class AuditFinding(Base):
    """Individual finding from an audit with SLA-tracked remediation."""
    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True)
    finding_ref = Column(String(20), unique=True, nullable=False, index=True)
    audit_id = Column(Integer, ForeignKey("audit_plans.id"), nullable=False, index=True)

    title = Column(String(300))
    description = Column(Text)
    finding_type = Column(String(50))  # nonconformity / observation / opportunity

    severity = Column(String(20))  # critical / major / minor
    framework_clause = Column(String(100))
    control_id = Column(String(20))

    # Assignment
    assignee_id = Column(Integer, ForeignKey("users.id"))

    # SLA
    remediation_due = Column(DateTime)
    remediation_completed = Column(DateTime)
    sla_breached = Column(Boolean, default=False)
    remediation_notes = Column(Text)

    status = Column(String(50), default="open")  # open / in_progress / closed / accepted

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    audit = relationship("AuditPlan", back_populates="findings")
    assignee = relationship("User", back_populates="audit_findings", foreign_keys=[assignee_id])


class GovernanceAction(Base):
    """
    Governance workflow action items — enforces Segregation of Duties.
    Risk raiser != risk closer.
    """
    __tablename__ = "governance_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_ref = Column(String(20), unique=True, nullable=False, index=True)
    risk_id = Column(Integer, ForeignKey("risks.id"), nullable=False, index=True)

    action_type = Column(String(100))  # treatment_approval / board_sign_off / escalation
    description = Column(Text)

    assigned_to_id = Column(Integer, ForeignKey("users.id"))
    raised_by_id = Column(Integer, ForeignKey("users.id"))  # Cannot == assigned_to for SoD

    status = Column(String(50), default="pending")  # pending / in_progress / complete / rejected
    due_date = Column(DateTime)
    completed_at = Column(DateTime)
    notes = Column(Text)

    # SoD validation
    sod_validated = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    risk = relationship("Risk", back_populates="governance_actions")
    assigned_to_user = relationship("User", back_populates="governance_actions", foreign_keys=[assigned_to_id])
    raised_by_user = relationship("User", foreign_keys=[raised_by_id])
