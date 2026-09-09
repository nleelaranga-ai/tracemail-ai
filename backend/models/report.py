"""
TraceMail AI Backend — Report Metadata Model
"""
from backend.database.connection import Base, Column, String, Integer, DateTime
from backend.utils.helpers import generate_uuid, utc_now


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("rep_"), index=True)
    investigation_id = Column(String(64), default="", index=True, nullable=False)
    report_format = Column(String(16), default="pdf", nullable=False)
    file_path = Column(String(500), default="", nullable=True)
    download_count = Column(Integer, default=0, nullable=False)
    generated_at = Column(DateTime, default=utc_now, nullable=False)
