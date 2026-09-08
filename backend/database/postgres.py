"""
TraceMail AI Backend — PostgreSQL Health & Connection Inspector
"""
from backend.database.connection import engine
from backend.utils.logger import logger

try:
    from sqlalchemy import text
except ImportError:
    text = None


def check_database_health() -> bool:
    """Performs a lightweight database connection check."""
    if engine is None or text is None:
        return True
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.warning(f"Database health check warning: {e}")
        return False
