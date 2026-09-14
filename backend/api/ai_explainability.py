"""
TraceMail AI Backend — AI Explainability Engine API Router
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.models.user import User
from backend.middleware.auth import get_current_user
from backend.services.explainability_service import ExplainabilityService

router = APIRouter(tags=["AI Explainability"])


@router.get("/api/ai/explainability/{investigation_id}")
def get_ai_explainability(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns mathematically grounded reason weights summing to the overall threat score."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view AI explainability details.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )

    if getattr(current_user, "role", "") != "admin":
        if inv.owner_user_id and inv.owner_user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{investigation_id}' not found."
            )

    res = ExplainabilityService.get_explainability(investigation_id, db)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )
    return res
