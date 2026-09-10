"""
TraceMail AI Backend — Investigations & Master Contracts Router (Section 6 & 9.1)
"""
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from typing import List
from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.schemas.report_schema import (
    InvestigationDetailResponse,
    InvestigationSummary,
    AIResult,
    ExtractedEntities,
    ThreatItem
)
from backend.schemas.email_schema import EmailUploadResponse
from backend.services.email_service import EmailService

router = APIRouter(tags=["Investigations"])


@router.post("/api/investigations", response_model=EmailUploadResponse, status_code=status.HTTP_200_OK)
@router.post("/api/v1/investigations", response_model=EmailUploadResponse, status_code=status.HTTP_200_OK, include_in_schema=False)
async def create_investigation(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Ingests raw .eml file, extracts headers/IOCs, runs AI + Threat intelligence, and persists."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename.")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded email file is empty.")

    inv = await EmailService.process_eml_file(db, content, file.filename)

    return EmailUploadResponse(
        investigationId=inv.id,
        scan_id=inv.id,
        status=inv.status,
        message="Email processed and analyzed successfully.",
        threat_score=inv.threat_score,
        risk_level=inv.risk_level,
        origin_city=inv.origin_city,
        origin_country=inv.origin_country
    )


@router.get("/api/investigations", response_model=List[InvestigationSummary])
@router.get("/api/v1/investigations", response_model=List[InvestigationSummary], include_in_schema=False)
def list_investigations(db: Session = Depends(get_db)):
    """Lists past investigations for dashboard history."""
    records = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(50).all()
    return [
        InvestigationSummary(
            id=r.id,
            status=r.status,
            sender=r.sender,
            subject=r.subject,
            receivedAt=r.received_at.isoformat() if r.received_at else "",
            verdict=r.verdict,
            phishingScore=r.threat_score if r.threat_score is not None else r.phishing_score
        )
        for r in records
    ]


@router.get("/api/investigations/{id}", response_model=InvestigationDetailResponse)
@router.get("/api/v1/investigations/{id}", response_model=InvestigationDetailResponse, include_in_schema=False)
def get_investigation_detail(id: str, db: Session = Depends(get_db)):
    """Master API Contract (Section 6 & 9.1): Returns complete case payload."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {id} not found.")

    entities_data = inv.entities or {}
    score = inv.threat_score if inv.threat_score is not None else inv.phishing_score
    ai_result = AIResult(
        phishingScore=score,
        verdict=inv.verdict,
        explanation=inv.explanation or "Analysis complete.",
        entities=ExtractedEntities(
            urls=entities_data.get("urls", []) if isinstance(entities_data, dict) else [],
            ips=entities_data.get("ips", []) if isinstance(entities_data, dict) else [],
            domains=entities_data.get("domains", []) if isinstance(entities_data, dict) else [],
            senderClaim=entities_data.get("senderClaim") if isinstance(entities_data, dict) else None,
            senderActual=entities_data.get("senderActual") if isinstance(entities_data, dict) else None
        )
    )

    threat_items = [
        ThreatItem(
            type=item.get("type", "ip"),
            value=item.get("value", ""),
            reputation=item.get("reputation", 0),
            geo=item.get("geo"),
            malicious=item.get("malicious", False)
        )
        for item in (inv.threat_results or [])
    ]

    return InvestigationDetailResponse(
        id=inv.id,
        status=inv.status,
        sender=inv.sender,
        recipient=inv.recipient,
        subject=inv.subject,
        receivedAt=inv.received_at.isoformat() if inv.received_at else "",
        aiResult=ai_result,
        threatResults=threat_items,
        mapUrl=f"/api/geo/map/{inv.id}",
        timelineUrl=f"/api/geo/timeline/{inv.id}",
        graphUrl=f"/api/geo/graph/{inv.id}",
        reportUrl=f"/api/report/pdf/{inv.id}",
        threat_score=score,
        threatScore=score,
        risk_level=inv.risk_level,
        riskLevel=inv.risk_level,
        origin_ip=inv.origin_ip,
        origin_city=inv.origin_city,
        origin_country=inv.origin_country,
        latitude=inv.latitude,
        longitude=inv.longitude,
        threat_intel=inv.threat_intel,
        threatIntel=inv.threat_intel,
        ai_analysis=inv.ai_analysis,
        aiAnalysis=inv.ai_analysis,
        timeline=inv.timeline,
        iocs=inv.iocs,
        entities=inv.entities,
        auth_results=inv.auth_results,
        authResults=inv.auth_results
    )
