"""
TraceMail AI Backend — SOC Analytics & Org Heatmap API Router
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from backend.database.connection import get_db, Session
from backend.services.soc_service import SocService

router = APIRouter(tags=["SOC Command Center"])


@router.get("/api/soc/overview")
def get_soc_overview(db: Session = Depends(get_db)):
    """Returns high-level threat telemetry, KPI counts, and brand impersonation statistics."""
    return SocService.get_overview(db)


@router.get("/api/org/heatmap")
def get_org_heatmap(db: Session = Depends(get_db)):
    """Returns departmental vulnerability metrics and repeated target statistics."""
    return SocService.get_org_heatmap(db)
