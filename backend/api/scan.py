"""
TraceMail AI Backend — Scan API
"""
from fastapi import APIRouter, HTTPException, status
from backend.schemas.scan_schema import ScanEmailRequest, ScanUrlRequest, ScanDomainRequest, ScanResultResponse
from backend.services.scan_service import ScanService
from backend.parsers.ioc_parser import IOCParser

router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])


@router.post("/email")
async def scan_email_content(req: ScanEmailRequest):
    """Scans raw email text and headers for phishing patterns."""
    iocs = IOCParser.extract_iocs(f"{req.headers}\n{req.emailBody}")
    result = await ScanService.query_ai_engine(
        email_body=req.emailBody,
        headers=req.headers,
        extracted_urls=iocs.get("urls", []),
        extracted_ips=iocs.get("ips", []),
        sender=""
    )
    return result


@router.post("/url", response_model=ScanResultResponse)
async def scan_url_indicator(req: ScanUrlRequest):
    """Scans a single URL against threat intelligence."""
    threat = await ScanService.query_url_threat(req.url)
    return ScanResultResponse(
        indicator=req.url,
        type="url",
        reputation_score=threat.get("vtPositives", 0) * 10,
        verdict=threat.get("category", "clean"),
        is_malicious=threat.get("malicious", False),
        details=threat
    )


@router.post("/domain", response_model=ScanResultResponse)
async def scan_domain_indicator(req: ScanDomainRequest):
    """Scans a domain for reputation and WHOIS age."""
    url = f"http://{req.domain}"
    threat = await ScanService.query_url_threat(url)
    return ScanResultResponse(
        indicator=req.domain,
        type="domain",
        reputation_score=threat.get("vtPositives", 0) * 10,
        verdict=threat.get("category", "clean"),
        is_malicious=threat.get("malicious", False),
        details=threat
    )
