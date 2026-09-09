"""
TraceMail AI — Master Backend Gateway Microservice
Smart India Hackathon 2026 (SIH26106)
Owned and Maintained by the Backend Team.
"""
import sys
from pathlib import Path

# Add repository root and backend directory to sys.path
_repo_root = str(Path(__file__).resolve().parent.parent)
_backend_dir = str(Path(__file__).resolve().parent)
for _p in [_repo_root, _backend_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI
from contextlib import asynccontextmanager

from backend.utils.constants import PROJECT_NAME, VERSION
from backend.utils.logger import logger
from backend.database.connection import init_db
from backend.database.seed import seed_database
from backend.middleware.cors import setup_cors
from backend.middleware.logging import RequestLoggingMiddleware
from backend.middleware.error_handler import setup_error_handlers
from backend.middleware.rate_limit import RateLimitMiddleware

# API Routers
from backend.api.auth import router as auth_router
from backend.api.investigations import router as investigations_router
from backend.api.email import router as email_router
from backend.api.scan import router as scan_router
from backend.api.threat import router as threat_router
from backend.api.maps import router as maps_router
from backend.api.report import router as report_router
from backend.api.admin import router as admin_router
from backend.api.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes database tables and default demo seeds on startup."""
    logger.info(f"Starting {PROJECT_NAME} v{VERSION}...")
    init_db()
    seed_database()
    logger.info(f"{PROJECT_NAME} gateway ready to process threat telemetry.")
    yield
    logger.info(f"Shutting down {PROJECT_NAME}...")


app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="Central API Hub, MIME Parser, and Microservice Orchestrator for TraceMail AI.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Eagerly initialize and seed demo records so they are immediately available
init_db()
seed_database()

# Register Middleware
setup_cors(app)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
setup_error_handlers(app)

# Register API Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(investigations_router)
app.include_router(email_router)
app.include_router(scan_router)
app.include_router(threat_router)
app.include_router(maps_router)
app.include_router(report_router)
app.include_router(admin_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
