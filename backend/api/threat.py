"""
TraceMail AI Backend — Threat Intelligence Integration Endpoints
"""
from fastapi import APIRouter, Query, HTTPException, Body
from typing import Optional, Dict, Any
from backend.services.scan_service import ScanService

router = APIRouter(tags=["Threat Intelligence"])


@router.get("/api/v1/threat/reputation")
async def get_threat_reputation(
    type: str = Query(..., description="Indicator type: 'ip' or 'url'"),
    value: str = Query(..., description="The IP address or URL string")
):
    """Unified reputation query across threat providers."""
    if type == "ip":
        return await ScanService.query_ip_threat(value)
    elif type == "url":
        return await ScanService.query_url_threat(value)
    else:
        raise HTTPException(status_code=400, detail="Invalid indicator type. Must be 'ip' or 'url'.")


@router.get("/api/threat/ip/{ip}")
async def get_ip_threat(ip: str):
    """Master API Contract: Resolves IP geolocation and Abuse score."""
    return await ScanService.query_ip_threat(ip)


@router.post("/api/threat/url")
async def check_url_threat(payload: Dict[str, str] = Body(...)):
    """Master API Contract: URL scanner verdict and detections."""
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' field in request body.")
    return await ScanService.query_url_threat(url)


@router.post("/api/threat/auth-check")
async def check_auth_headers(payload: Dict[str, str] = Body(...)):
    """Master API Contract: Evaluates SPF, DKIM, DMARC from raw headers."""
    raw_headers = payload.get("rawHeaders")
    if not raw_headers:
        raise HTTPException(status_code=400, detail="Missing 'rawHeaders' field.")
    return await ScanService.query_auth_check(raw_headers)
