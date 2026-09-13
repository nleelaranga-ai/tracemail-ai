"""
TraceMail AI Backend — Health Check Endpoint
"""
import os
from fastapi import APIRouter
from datetime import datetime, timezone
from backend.schemas.response_schema import HealthResponse
from backend.database.postgres import check_database_health, check_database_connection
from backend.utils.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
@router.get("/api/v1/health", response_model=HealthResponse, include_in_schema=False)
def health_check():
    """Liveness and readiness health probe for Render / Docker / CI/CD."""
    db_ok = check_database_health()
    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        service="backend-api",
        version="1.1.0-live-intel",
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@router.get("/health/database")
@router.get("/api/v1/health/database", include_in_schema=False)
def database_health():
    """Detailed database connectivity health probe."""
    db_ok, db_type, db_err = check_database_connection()
    res = {
        "status": "healthy" if db_ok else "unhealthy",
        "database": db_type,
        "connected": db_ok,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if not db_ok:
        res["error"] = db_err
    return res


@router.get("/health/apis")
@router.get("/api/v1/health/apis", include_in_schema=False)
def apis_health():
    """External threat intelligence APIs and feeds availability status."""
    has_live_keys = any([
        settings.VIRUSTOTAL_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.IPINFO_API_KEY,
        settings.URLSCAN_API_KEY,
        settings.GOOGLE_SAFE_BROWSING_API_KEY,
    ])
    all_live_keys = all([
        settings.VIRUSTOTAL_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.IPINFO_API_KEY,
        settings.URLSCAN_API_KEY,
        settings.GOOGLE_SAFE_BROWSING_API_KEY,
    ])
    
    core_live_keys = all([
        settings.VIRUSTOTAL_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.IPINFO_API_KEY,
    ])
    if not settings.USE_MOCK_THREAT_INTEL and (all_live_keys or core_live_keys):
        mode = "live"
    elif has_live_keys:
        mode = "hybrid"
    else:
        mode = "simulation"

    mock_active = settings.USE_MOCK_THREAT_INTEL
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT,
        "mode": "fallback" if mock_active else mode,
        "use_mock_threat_intel": mock_active,
        "enable_demo_seed": os.getenv("ENABLE_DEMO_SEED", "not_set"),
        "apis": {
            "virustotal": {
                "name": "VirusTotal v3",
                "configured": bool(settings.VIRUSTOTAL_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.VIRUSTOTAL_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.VIRUSTOTAL_API_KEY),
                "status": "simulation_ready" if not settings.VIRUSTOTAL_API_KEY else ("fallback" if mock_active else "live")
            },
            "abuseipdb": {
                "name": "AbuseIPDB v2",
                "configured": bool(settings.ABUSEIPDB_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.ABUSEIPDB_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.ABUSEIPDB_API_KEY),
                "status": "simulation_ready" if not settings.ABUSEIPDB_API_KEY else ("fallback" if mock_active else "live")
            },
            "ipinfo": {
                "name": "IPinfo Geolocation & ASN",
                "configured": bool(settings.IPINFO_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.IPINFO_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.IPINFO_API_KEY),
                "status": "simulation_ready" if not settings.IPINFO_API_KEY else ("fallback" if mock_active else "live")
            },
            "urlscan": {
                "name": "URLScan.io",
                "configured": bool(settings.URLSCAN_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.URLSCAN_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.URLSCAN_API_KEY),
                "status": "simulation_ready" if not settings.URLSCAN_API_KEY else ("fallback" if mock_active else "live")
            },
            "google_safe_browsing": {
                "name": "Google Safe Browsing v4",
                "configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
                "status": "simulation_ready" if not settings.GOOGLE_SAFE_BROWSING_API_KEY else ("fallback" if mock_active else "live")
            },
            "groq": {
                "name": "Groq Cloud Llama-3 AI Engine",
                "configured": bool(settings.GROQ_API_KEY),
                "reachable": True,
                "authenticated": bool(settings.GROQ_API_KEY),
                "rate_limited": False,
                "fallback_active": mock_active or not bool(settings.GROQ_API_KEY),
                "status": "simulation_ready" if not settings.GROQ_API_KEY else ("fallback" if mock_active else "live")
            },
            "rdap_whois": {
                "name": "ICANN RDAP / WHOIS",
                "configured": True,
                "reachable": True,
                "authenticated": True,
                "rate_limited": False,
                "fallback_active": False,
                "status": "live"
            },
            "dns_resolver": {
                "name": "SPF / DKIM / DMARC DNS Resolver",
                "configured": True,
                "reachable": True,
                "authenticated": True,
                "rate_limited": False,
                "fallback_active": False,
                "status": "live"
            },
            "geoip": {
                "name": "TraceMail GeoIP Service",
                "configured": True,
                "reachable": True,
                "authenticated": True,
                "rate_limited": False,
                "fallback_active": False,
                "status": "live"
            }
        }
    }

