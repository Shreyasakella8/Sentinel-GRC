"""SENTINEL-GRC — User Model"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="read_only")
    department = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owned_risks = relationship("Risk", back_populates="owner", foreign_keys="Risk.owner_id")
    audit_findings = relationship("AuditFinding", back_populates="assignee")
    governance_actions = relationship("GovernanceAction", back_populates="assigned_to_user", foreign_keys="GovernanceAction.assigned_to_id")
