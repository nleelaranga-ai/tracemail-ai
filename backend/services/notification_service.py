"""
TraceMail AI Backend — Alert & Notification Service
"""
from typing import Dict, Any
from backend.utils.logger import logger


class NotificationService:
    @staticmethod
    def send_threat_alert(investigation_id: str, verdict: str, score: int, recipient: str = "soc-alerts@tracemail.local") -> bool:
        if verdict in ("phishing", "critical", "high") or score >= 70:
            logger.warning(
                f"[ALERT] High-severity email threat detected! "
                f"Investigation={investigation_id}, Verdict={verdict}, Score={score}, Target={recipient}"
            )
            # In production: dispatches Webhook / Slack / Email alert
            return True
        return False
