"""
TraceMail AI Backend — Health Check Endpoint
"""
from fastapi import APIRouter
from datetime import datetime, timezone
from backend.schemas.response_schema import HealthResponse
from backend.database.postgres import check_database_health
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
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@router.get("/health/database")
@router.get("/api/v1/health/database", include_in_schema=False)
def database_health():
    """Detailed database connectivity health probe."""
    db_ok = check_database_health()
    return {
        "status": "healthy" if db_ok else "unhealthy",
        "database": "postgresql" if "postgresql" in settings.DATABASE_URL else "sqlite",
        "connected": db_ok,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/health/apis")
@router.get("/api/v1/health/apis", include_in_schema=False)
def apis_health():
    """External threat intelligence APIs and feeds availability status."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "apis": {
            "virustotal": {
                "name": "VirusTotal v3",
                "configured": bool(settings.VIRUSTOTAL_API_KEY),
                "status": "live" if settings.VIRUSTOTAL_API_KEY else "simulation_ready"
            },
            "abuseipdb": {
                "name": "AbuseIPDB v2",
                "configured": bool(settings.ABUSEIPDB_API_KEY),
                "status": "live" if settings.ABUSEIPDB_API_KEY else "simulation_ready"
            },
            "urlscan": {
                "name": "URLScan.io",
                "configured": bool(settings.URLSCAN_API_KEY),
                "status": "live" if settings.URLSCAN_API_KEY else "simulation_ready"
            },
            "rdap_whois": {
                "name": "ICANN RDAP / WHOIS",
                "configured": True,
                "status": "live"
            },
            "geoip": {
                "name": "TraceMail GeoIP Service",
                "configured": True,
                "status": "live"
            }
        }
    }
