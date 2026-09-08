"""
TraceMail AI Backend — Common Helpers
"""
import uuid
from datetime import datetime, timezone


def generate_uuid(prefix: str = "") -> str:
    unique = str(uuid.uuid4())
    return f"{prefix}{unique}" if prefix else unique


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
