"""
TraceMail AI Backend — AI Explainability Engine API Router
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.services.explainability_service import ExplainabilityService

router = APIRouter(tags=["AI Explainability"])


@router.get("/api/ai/explainability/{investigation_id}")
def get_ai_explainability(investigation_id: str, db: Session = Depends(get_db)):
    """Returns mathematically grounded reason weights summing to the overall threat score."""
    res = ExplainabilityService.get_explainability(investigation_id, db)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )
    return res
