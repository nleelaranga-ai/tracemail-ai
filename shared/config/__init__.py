"""
TraceMail AI — Shared Config Package
"""

from shared.config.settings import get_settings, Settings
from shared.config.logging import get_logger

__all__ = ["get_settings", "Settings", "get_logger"]
