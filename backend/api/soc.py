"""
TraceMail AI Backend — SOC Analytics & Org Heatmap API Router
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.services.soc_service import SocService
from backend.middleware.auth import get_current_user
from backend.models.user import User

router = APIRouter(tags=["SOC Command Center"])


@router.get("/api/soc/overview")
def get_soc_overview(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns high-level threat telemetry, KPI counts, and brand impersonation statistics. Requires authentication."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view SOC analytics.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return SocService.get_overview(db)


@router.get("/api/org/heatmap")
def get_org_heatmap(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns departmental vulnerability metrics and repeated target statistics. Requires authentication."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view organization heatmap.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return SocService.get_org_heatmap(db)
