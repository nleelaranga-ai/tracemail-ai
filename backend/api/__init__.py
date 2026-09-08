# backend/api/__init__.py
from .auth import router as auth_router
from .investigations import router as investigations_router
from .email import router as email_router
from .scan import router as scan_router
from .threat import router as threat_router
from .maps import router as maps_router
from .report import router as report_router
from .admin import router as admin_router
from .health import router as health_router
