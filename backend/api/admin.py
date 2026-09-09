"""
TraceMail AI Backend — Admin & Analytics Endpoints
"""
from fastapi import APIRouter, Depends
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.models.audit_log import AuditLog

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


@router.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    """Provides high-level investigation statistics for the admin dashboard."""
    total = db.query(Investigation).count()
    phishing = db.query(Investigation).filter(Investigation.verdict == "phishing").count()
    suspicious = db.query(Investigation).filter(Investigation.verdict == "suspicious").count()
    safe = db.query(Investigation).filter(Investigation.verdict == "safe").count()

    return {
        "total_investigations": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "threat_detection_rate": round((phishing + suspicious) / max(total, 1) * 100, 1)
    }


@router.get("/audit-logs")
def get_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Returns recent administrative and investigation audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "action": l.action,
            "target_id": l.target_id,
            "ip_address": l.ip_address,
            "timestamp": l.timestamp.isoformat(),
            "details": l.details
        }
        for l in logs
    ]
