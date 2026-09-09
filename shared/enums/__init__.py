"""
TraceMail AI — Shared Enums
Single source of truth for enumeration values across all modules.
"""

from enum import Enum


class RiskLevel(str, Enum):
    """Normalized risk classification for emails, IPs, and domains."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvestigationStatus(str, Enum):
    """Status lifecycle of an email forensic case."""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatType(str, Enum):
    """Categorized threat taxonomy."""
    PHISHING = "phishing"
    MALWARE = "malware"
    SPOOFING = "spoofing"
    BEC = "bec"  # Business Email Compromise / CEO Fraud
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"


class AuthVerdict(str, Enum):
    """Email authentication check results (SPF, DKIM, DMARC)."""
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    SOFTFAIL = "softfail"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
