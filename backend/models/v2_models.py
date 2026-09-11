"""
TraceMail AI Backend — Master Plan v2 ORM Models
Adds Gmail Accounts, Inbox Scan Results, Evidence Records, Attachment Scans, and Org Metrics.
"""
from datetime import datetime, timezone
from backend.database.connection import Base, Column, String, Integer, Boolean, DateTime, Text, JSON
from backend.utils.helpers import generate_uuid, utc_now


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("gacc_"), index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, default="", nullable=True)
    token_expiry = Column(DateTime, default=utc_now, nullable=True)
    connected = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_scanned_at = Column(DateTime, default=utc_now, nullable=True)


class InboxScanResult(Base):
    __tablename__ = "inbox_scan_results"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("inb_"), index=True)
    account_email = Column(String(255), nullable=False, index=True)
    message_id = Column(String(255), nullable=False)
    sender = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=False)
    snippet = Column(Text, default="", nullable=True)
    risk = Column(String(50), default="Safe", nullable=False)  # Safe, Suspicious, Critical
    threat_score = Column(Integer, default=0, nullable=False)
    verdict = Column(String(50), default="safe", nullable=False)
    scanned_at = Column(DateTime, default=utc_now, nullable=False)
    investigation_id = Column(String(64), default="", nullable=True)


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("evd_"), index=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False)
    original_hash = Column(String(64), nullable=False)
    investigator = Column(String(255), default="SOC Lead Analyst", nullable=False)
    status = Column(String(50), default="Verified", nullable=False)  # Verified, Tampered, Exported
    raw_content = Column(Text, default="", nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    verified_at = Column(DateTime, default=utc_now, nullable=True)
    custody_notes = Column(Text, default="Chain of custody initiated at ingestion.", nullable=True)


class AttachmentScan(Base):
    __tablename__ = "attachment_scans"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("att_"), index=True)
    investigation_id = Column(String(64), default="", nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    file_type = Column(String(50), default="unknown", nullable=False)
    sha256 = Column(String(64), nullable=False)
    size_bytes = Column(Integer, default=0, nullable=False)
    malicious = Column(Boolean, default=False, nullable=False)
    verdict = Column(String(50), default="Clean", nullable=False)
    engine = Column(String(100), default="TraceMail Heuristics + VirusTotal", nullable=False)
    details = Column(JSON, default=dict, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class OrgMetric(Base):
    __tablename__ = "org_metrics"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("org_"), index=True)
    department = Column(String(100), nullable=False, unique=True)
    threat_count = Column(Integer, default=0, nullable=False)
    phishing_count = Column(Integer, default=0, nullable=False)
    safe_count = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(50), default="Low", nullable=False)
    top_attack_type = Column(String(100), default="Credential Harvesting", nullable=False)
    last_attack_at = Column(DateTime, default=utc_now, nullable=True)
