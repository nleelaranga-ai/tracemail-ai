"""
TraceMail AI Backend — Admin & Analytics Endpoints
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.middleware.auth import get_current_user

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


@router.get("/analytics")
def get_analytics(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Provides high-level investigation statistics for the admin dashboard."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view admin analytics.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if getattr(current_user, "role", "") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to access administrative resources."
        )

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
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns recent administrative and investigation audit logs."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view audit logs.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if getattr(current_user, "role", "") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to access administrative resources."
        )

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
