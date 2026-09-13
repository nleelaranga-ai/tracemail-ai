"""
TraceMail AI Backend — Evidence Locker & Legal Custody API Router
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from backend.database.connection import get_db, Session
from backend.services.evidence_service import EvidenceService
from backend.middleware.auth import get_current_user
from backend.models.user import User

router = APIRouter(tags=["Evidence Locker"])


@router.get("/api/evidence")
def list_evidence_records(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Lists all cryptographic evidence items stored in the locker with strict tenant isolation."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view Evidence Locker.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return EvidenceService.list_records(db, current_user=current_user)


@router.get("/api/evidence/{investigation_id}")
def get_evidence_record(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns court-admissible custody chain and SHA-256 integrity record."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view Evidence record.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    rec = EvidenceService.get_or_create_record(investigation_id, db, current_user=current_user)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found in Evidence Locker."
        )
    return rec


@router.post("/api/evidence/{investigation_id}/verify")
def verify_evidence_record(
    investigation_id: str,
    simulated_corrupt: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Recomputes SHA-256 checksum and verifies evidence against post-ingestion tampering."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to verify Evidence integrity.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    res = EvidenceService.verify_integrity(investigation_id, db, simulated_corrupt=simulated_corrupt, current_user=current_user)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found in Evidence Locker."
        )
    return res
