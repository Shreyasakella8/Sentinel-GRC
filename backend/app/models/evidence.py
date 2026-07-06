"""
SENTINEL-GRC — Evidence Vault Model
chain_hash column added — stores the composite block hash that ties
this entry cryptographically to its predecessor.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.db.database import Base


class EvidenceEntry(Base):
    """
    Tamper-evident evidence record.
    Each entry:
      - SHA-256 hashes the evidence payload  (content_hash)
      - HMAC-SHA256 signs it                 (hmac_signature)
      - Links to the previous block's hash   (previous_entry_hash)
      - Stores the composite chain hash      (chain_hash)  ← NEW
      - MinIO object key for the full blob   (raw_data_key)
    """
    __tablename__ = "evidence_entries"

    id                  = Column(Integer, primary_key=True, index=True)
    entry_ref           = Column(String(80), unique=True, nullable=False, index=True)

    # Linkage
    control_id          = Column(String(20), nullable=False, index=True)
    risk_id             = Column(Integer, ForeignKey("risks.id"), nullable=True)

    # Evidence data
    evidence_type       = Column(String(50))
    summary             = Column(Text)
    raw_data_key        = Column(String(300))

    # Cryptographic integrity
    content_hash        = Column(String(64), nullable=False)
    hmac_signature      = Column(String(64), nullable=False)
    previous_entry_hash = Column(String(64))
    chain_hash          = Column(String(64))   # SHA-256(content_hash + previous_entry_hash)
    chain_valid         = Column(Boolean, default=True)

    # Compliance mapping
    frameworks_covered  = Column(Text)
    iso27001_clause     = Column(String(50))
    nist_csf            = Column(String(50))
    soc2_criteria       = Column(String(50))

    # Audit metadata
    collected_by        = Column(String(100))
    collected_at        = Column(DateTime, default=datetime.utcnow, index=True)
    verified_at         = Column(DateTime)
    verified_by_id      = Column(Integer, ForeignKey("users.id"), nullable=True)

    risk        = relationship("Risk", back_populates="evidence_entries")
    verified_by = relationship("User", foreign_keys=[verified_by_id])
