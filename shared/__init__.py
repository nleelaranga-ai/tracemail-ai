"""
TraceMail AI — Shared Integration Layer
Centralized contracts, validation, configuration, and enums for all modules.
"""

from shared.enums import RiskLevel, InvestigationStatus, ThreatType, AuthVerdict
from shared.config.settings import get_settings, Settings
from shared.config.logging import get_logger

__version__ = "1.0.0"
__all__ = [
    "RiskLevel",
    "InvestigationStatus",
    "ThreatType",
    "AuthVerdict",
    "get_settings",
    "Settings",
    "get_logger",
]
