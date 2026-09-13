"""
TraceMail AI Backend — PostgreSQL Health & Connection Inspector
"""
from backend.database.connection import engine
from backend.utils.logger import logger

try:
    from sqlalchemy import text
except ImportError:
    text = None


def check_database_connection() -> tuple[bool, str]:
    """Performs a lightweight database connection check and returns (ok, error_detail)."""
    if engine is None or text is None:
        return True, "in-memory"
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, "connected"
    except Exception as e:
        logger.warning(f"Database health check warning: {e}")
        return False, str(e)


def check_database_health() -> bool:
    """Performs a lightweight database connection check."""
    ok, _ = check_database_connection()
    return ok
