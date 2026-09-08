"""
TraceMail AI Backend — Threat Result Model
"""
from backend.database.connection import Base, Column, String, Integer, Boolean, DateTime, JSON
from backend.utils.helpers import generate_uuid, utc_now


class ThreatResult(Base):
    __tablename__ = "threat_results"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("thr_"), index=True)
    investigation_id = Column(String(64), default="", index=True, nullable=True)
    indicator_type = Column(String(32), default="", nullable=False)
    indicator_value = Column(String(500), default="", nullable=False)
    reputation_score = Column(Integer, default=0, nullable=False)
    is_malicious = Column(Boolean, default=False, nullable=False)
    geo_location = Column(String(255), default="", nullable=True)
    details = Column(JSON, default=dict, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
