"""
TraceMail AI Backend — Evidence Locker & Legal Custody API Router
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query
from backend.database.connection import get_db, Session
from backend.services.evidence_service import EvidenceService

router = APIRouter(tags=["Evidence Locker"])


@router.get("/api/evidence")
def list_evidence_records(db: Session = Depends(get_db)):
    """Lists all cryptographic evidence items stored in the locker."""
    return EvidenceService.list_records(db)


@router.get("/api/evidence/{investigation_id}")
def get_evidence_record(investigation_id: str, db: Session = Depends(get_db)):
    """Returns court-admissible custody chain and SHA-256 integrity record."""
    return EvidenceService.get_or_create_record(investigation_id, db)


@router.post("/api/evidence/{investigation_id}/verify")
def verify_evidence_record(investigation_id: str, simulated_corrupt: bool = Query(False), db: Session = Depends(get_db)):
    """Recomputes SHA-256 checksum and verifies evidence against post-ingestion tampering."""
    return EvidenceService.verify_integrity(investigation_id, db, simulated_corrupt=simulated_corrupt)
