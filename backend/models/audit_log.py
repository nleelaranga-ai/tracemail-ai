"""
TraceMail AI Backend — Audit Log Model
"""
from backend.database.connection import Base, Column, String, DateTime, JSON
from backend.utils.helpers import generate_uuid, utc_now


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("aud_"), index=True)
    user_id = Column(String(64), default="", nullable=True)
    action = Column(String(100), default="", nullable=False)
    target_id = Column(String(100), default="", nullable=True)
    ip_address = Column(String(64), default="", nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    details = Column(JSON, default=dict, nullable=True)
