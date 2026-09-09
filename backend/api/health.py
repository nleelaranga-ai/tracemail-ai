"""
TraceMail AI Backend — Health Check Endpoint
"""
from fastapi import APIRouter
from datetime import datetime, timezone
from backend.schemas.response_schema import HealthResponse
from backend.database.postgres import check_database_health

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
