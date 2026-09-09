"""
TraceMail AI Backend — Investigation & Scan Models
"""
from backend.database.connection import Base, Column, String, Integer, DateTime, Text, JSON
from backend.utils.helpers import generate_uuid, utc_now


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("inv_"), index=True)
    status = Column(String(50), default="processing", nullable=False)
    sender = Column(String(255), default="", nullable=True)
    recipient = Column(String(255), default="", nullable=True)
    subject = Column(String(500), default="", nullable=True)
    received_at = Column(DateTime, default=utc_now, nullable=False)
    
    phishing_score = Column(Integer, default=0, nullable=False)
    verdict = Column(String(50), default="suspicious", nullable=False)
    explanation = Column(Text, default="", nullable=True)
    
    raw_headers = Column(Text, default="", nullable=True)
    body_text = Column(Text, default="", nullable=True)
    entities = Column(JSON, default=dict, nullable=True)
    auth_results = Column(JSON, default=dict, nullable=True)
    hop_timeline = Column(JSON, default=list, nullable=True)
    geojson_map = Column(JSON, default=dict, nullable=True)
    attack_graph = Column(JSON, default=dict, nullable=True)
    threat_results = Column(JSON, default=list, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, nullable=False)
