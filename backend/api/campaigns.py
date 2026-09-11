"""
TraceMail AI Backend — Campaign Intelligence API Router
Endpoints for querying correlated attack campaigns and threat clusters.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.services.campaign_service import CampaignService

router = APIRouter(tags=["Campaigns"])


@router.get("/api/campaigns", response_model=List[Dict[str, Any]])
@router.get("/api/v1/campaigns", response_model=List[Dict[str, Any]], include_in_schema=False)
def list_campaigns(db: Session = Depends(get_db)):
    """
    Returns high-level threat campaigns dynamically correlated from investigation telemetry.
    """
    return CampaignService.correlate_investigations(db)


@router.get("/api/campaigns/{campaign_id}", response_model=Dict[str, Any])
@router.get("/api/v1/campaigns/{campaign_id}", response_model=Dict[str, Any], include_in_schema=False)
def get_campaign_detail(campaign_id: str, db: Session = Depends(get_db)):
    """
    Returns full campaign dossier with IOC bundle, attack timeline, and linked cases.
    """
    detail = CampaignService.get_campaign_detail(campaign_id, db)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found."
        )
    return detail
