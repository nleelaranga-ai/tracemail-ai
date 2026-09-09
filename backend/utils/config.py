"""
TraceMail AI Backend — Configuration Loader
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # App
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tracemail-sih-2026-super-secret-key-32chars")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "tracemail-jwt-secret-key-production-ready")
    
    # Database (Defaults to SQLite for instant local zero-dependency execution, or PostgreSQL if configured)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{ROOT_DIR / 'tracemail.db'}"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://localhost:8001",
        "*"
    ]
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # Service Endpoints
    THREAT_SERVICE_URL: str = os.getenv("THREAT_SERVICE_URL", "http://localhost:8001")
    AI_SERVICE_URL: str = os.getenv("AI_SERVICE_URL", "http://localhost:8002")
    MAPS_SERVICE_URL: str = os.getenv("MAPS_SERVICE_URL", "http://localhost:8003")
    REPORTS_SERVICE_URL: str = os.getenv("REPORTS_SERVICE_URL", "http://localhost:8004")

    class Config:
        case_sensitive = True
        extra = "allow"


settings = Settings()
