"""SENTINEL-GRC — Control Execution Results Model (TimescaleDB time-series)"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base


class ControlResult(Base):
    """
    Every control runner execution is stored here.
    TimescaleDB hypertable on executed_at for efficient time-range queries.
    """
    __tablename__ = "control_results"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(20), nullable=False, index=True)
    control_name = Column(String(200))

    # Result
    status = Column(String(20), nullable=False)  # pass / fail / error / warning
    passed = Column(Boolean, nullable=False)
    finding = Column(Text)               # Human-readable finding description
    raw_output = Column(Text)            # Raw JSON output from runner
    evidence_hash = Column(String(64))   # SHA-256 of raw_output
    evidence_key = Column(String(300))   # MinIO object key

    # FAIR Risk contribution
    risk_contribution_gbp = Column(Float, default=0)

    # Execution metadata
    executed_at = Column(DateTime, default=datetime.utcnow, index=True)
    execution_duration_ms = Column(Integer)
    runner_version = Column(String(20))

    # Linked risk record (auto-created on failure)
    risk_id = Column(Integer, ForeignKey("risks.id"), nullable=True)
    risk = relationship("Risk", back_populates="control_results")


class ControlSchedule(Base):
    """Tracks when each control is next due to run."""
    __tablename__ = "control_schedules"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(20), unique=True, nullable=False, index=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime, index=True)
    frequency_hours = Column(Integer, default=24)
    is_enabled = Column(Boolean, default=True)
    consecutive_failures = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
