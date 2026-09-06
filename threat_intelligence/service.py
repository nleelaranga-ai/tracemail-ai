"""
TraceMail AI — Threat Intelligence FastAPI Microservice
Fulfills the Section 6 Master API Contracts for IP, URL, DNS authentication, and composite threat scoring.
"""

from typing import Dict, Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from shared.interfaces.contracts import (
    IPThreatResponse,
    URLThreatRequest,
    URLThreatResponse,
    AuthCheckRequest,
    AuthCheckResponse,
    UnifiedThreatReport,
)
from shared.validation.validators import is_valid_ip, is_valid_url
from shared.config.logging import get_logger
from threat_intelligence.geo.geo_client import geo_client
from threat_intelligence.virustotal.vt_client import vt_client
from threat_intelligence.dns.auth_check import dns_checker
from threat_intelligence.reputation.scorer import reputation_scorer

logger = get_logger("ThreatIntelService")

app = FastAPI(
    title="TraceMail AI — Threat Intelligence API",
    description="Cybersecurity intelligence microservice providing IP reputation, URL verdicts, DNS/SPF/DKIM/DMARC auth, and threat scoring.",
    version="1.0.0",
)

# Enable CORS for Next.js frontend (port 3000) and Backend (port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Health check endpoint for Docker and load balancer probes."""
    return {
        "status": "healthy",
        "service": "threat-intelligence",
        "version": "1.0.0",
    }


# ==============================================================================
# SECTION 6 MASTER API CONTRACT ENDPOINTS
# ==============================================================================

@app.get(
    "/api/threat/ip/{ip}",
    response_model=IPThreatResponse,
    tags=["Threat Intelligence"],
    summary="Enrich IP with Geolocation, ISP, ASN, and Abuse Confidence Score",
)
async def get_ip_threat(ip: str) -> IPThreatResponse:
    """
    Input: IP address
    Output: Geolocation, reputation, ASN, ISP, abuseScore, malicious flag.
    Strictly conforms to Master API Contract Section 6.
    """
    logger.info(f"Received threat query for IP: {ip}")
    return await geo_client.get_ip_threat(ip)


@app.post(
    "/api/threat/url",
    response_model=URLThreatResponse,
    tags=["Threat Intelligence"],
    summary="Scan URL for Phishing and Malware Verdicts",
)
async def scan_url_threat(payload: URLThreatRequest) -> URLThreatResponse:
    """
    Input: URL string
    Output: Malicious verdict, category, scan date, vendor positives.
    Strictly conforms to Master API Contract Section 6.
    """
    logger.info(f"Received threat scan for URL: {payload.url}")
    return await vt_client.scan_url(payload.url)


@app.post(
    "/api/threat/auth-check",
    response_model=AuthCheckResponse,
    tags=["Threat Intelligence"],
    summary="Validate SPF, DKIM, and DMARC from Email Headers with WHOIS Data",
)
async def check_email_authentication(payload: AuthCheckRequest) -> AuthCheckResponse:
    """
    Input: Raw email headers
    Output: SPF/DKIM/DMARC pass/fail, domain age, registrar name.
    Strictly conforms to Master API Contract Section 6.
    """
    logger.info("Received email authentication validation request")
    return await dns_checker.check_authentication(payload.rawHeaders)


@app.post(
    "/api/threat/composite",
    response_model=UnifiedThreatReport,
    tags=["Threat Intelligence"],
    summary="Generate Composite Threat Intelligence JSON Report",
)
async def generate_composite_threat_report(
    auth: AuthCheckResponse,
    ip: str = "185.220.101.4",
    url: str = "http://paypa1-secure.com/login",
) -> UnifiedThreatReport:
    """
    Aggregates threat intelligence across IP, URL, and DNS layers into a single threat score (0-100).
    Directly consumed by Backend Hub (Backend Team).
    """
    ip_threat = await geo_client.get_ip_threat(ip)
    url_threat = await vt_client.scan_url(url)

    return reputation_scorer.calculate_composite_report(
        auth_check=auth,
        ip_threats=[ip_threat],
        url_threats=[url_threat],
    )
