"""SENTINEL-GRC — Risk Register Model (FAIR Methodology)"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base


class Risk(Base):
    """
    Risk register entry. Financial values calculated via FAIR Monte Carlo simulation.
    """
    __tablename__ = "risks"

    id = Column(Integer, primary_key=True, index=True)
    risk_ref = Column(String(20), unique=True, nullable=False, index=True)  # e.g. RISK-0042
    title = Column(String(300), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # cyber / operational / compliance / third_party

    # Asset information
    asset_name = Column(String(200))
    asset_type = Column(String(100))  # server / database / application / network / data
    asset_value_gbp = Column(Float, default=0)  # Primary asset value
    data_sensitivity = Column(String(50))  # public / internal / confidential / restricted

    # FAIR Risk Factors
    threat_event_frequency = Column(Float)    # TEF: events per year
    vulnerability_probability = Column(Float) # Probability 0-1 that threat succeeds
    primary_loss_magnitude_gbp = Column(Float)   # PLM: direct financial loss
    secondary_loss_magnitude_gbp = Column(Float) # SLM: reputational + regulatory
    regulatory_fine_exposure_gbp = Column(Float, default=0)

    # Monte Carlo Results (updated by risk engine)
    annualised_loss_expectancy_gbp = Column(Float)  # ALE: mean annual loss
    ale_10th_percentile_gbp = Column(Float)          # Best case
    ale_90th_percentile_gbp = Column(Float)          # Worst case
    exploitation_probability_12m = Column(Float)     # P(exploit) within 12 months
    last_monte_carlo_run = Column(DateTime)

    # Risk lifecycle
    status = Column(String(50), default="open")
    # open / under_treatment / accepted / transferred / closed
    severity = Column(String(20))   # critical / high / medium / low
    treatment = Column(String(50))  # accept / mitigate / transfer / avoid

    # Ownership & governance (Segregation of Duties: raiser != closer)
    raised_by_id = Column(Integer, ForeignKey("users.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    board_approved = Column(Boolean, default=False)
    board_approved_at = Column(DateTime)
    board_threshold_exceeded = Column(Boolean, default=False)  # Requires board sign-off

    # Treatment details
    treatment_plan = Column(Text)
    treatment_due_date = Column(DateTime)
    treatment_cost_gbp = Column(Float)

    # Escalation
    escalated = Column(Boolean, default=False)
    escalated_at = Column(DateTime)
    escalation_level = Column(Integer, default=0)

    # Source
    source = Column(String(100))  # control_runner / manual / threat_feed / audit
    source_control_id = Column(String(20))
    linked_cve = Column(String(50))
    linked_mitre_technique = Column(String(50))

    # Framework compliance
    frameworks_impacted = Column(JSON, default=list)  # ["ISO27001", "SOC2"]

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime)

    # Relationships
    owner = relationship("User", back_populates="owned_risks", foreign_keys=[owner_id])
    control_results = relationship("ControlResult", back_populates="risk")
    evidence_entries = relationship("EvidenceEntry", back_populates="risk")
    governance_actions = relationship("GovernanceAction", back_populates="risk")


class RiskScore(Base):
    """
    Time-series risk score snapshots.
    TimescaleDB hypertable on recorded_at.
    """
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    risk_id = Column(Integer, ForeignKey("risks.id"), nullable=False, index=True)
    ale_gbp = Column(Float, nullable=False)
    severity = Column(String(20))
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)
    trigger = Column(String(100))  # What caused this recalculation
