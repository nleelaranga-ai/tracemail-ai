"""
TraceMail AI Backend — Consolidated Relational Database Models
Exports all SQLAlchemy models for Base.metadata DDL generation & migrations.
"""
from .user import User
from .scan import (
    Investigation,
    EmailRecord,
    ScanRecord,
    AIResultRecord,
    HeaderRecord,
    IOCEntityRecord
)
from .threat import ThreatResult
from .report import Report
from .audit_log import AuditLog
from .investigation_geo import InvestigationGeoCache
from .v2_models import (
    GmailAccount,
    InboxScanResult,
    EvidenceRecord,
    AttachmentScan,
    OrgMetric
)

__all__ = [
    "User",
    "Investigation",
    "EmailRecord",
    "ScanRecord",
    "AIResultRecord",
    "HeaderRecord",
    "IOCEntityRecord",
    "ThreatResult",
    "Report",
    "AuditLog",
    "InvestigationGeoCache",
    "GmailAccount",
    "InboxScanResult",
    "EvidenceRecord",
    "AttachmentScan",
    "OrgMetric"
]

