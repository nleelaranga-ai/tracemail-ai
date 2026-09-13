"""
TraceMail AI Backend — PostgreSQL Health & Connection Inspector
"""
from backend.database.connection import engine
from backend.utils.logger import logger

try:
    from sqlalchemy import text
except ImportError:
    text = None


def check_database_connection() -> tuple[bool, str, str]:
    """
    Performs a lightweight database connection check and returns (ok, provider_type, error_detail).
    provider_type: 'postgresql', 'sqlite', or 'in-memory'
    """
    if engine is None or text is None:
        return True, "in-memory", "in-memory"

    provider_type = getattr(engine, "name", "unknown")
    if provider_type not in ("postgresql", "sqlite"):
        from backend.utils.config import settings
        provider_type = "postgresql" if "postgres" in settings.DATABASE_URL.lower() else "sqlite"

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, provider_type, "connected"
    except Exception as e:
        logger.warning(f"Database health check warning: {e}")
        return False, provider_type, str(e)


def check_database_health() -> bool:
    """Performs a lightweight database connection check."""
    ok, _, _ = check_database_connection()
    return ok
