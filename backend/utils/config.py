"""
TraceMail AI Backend — Configuration Loader
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
# Automatically load .env from root or backend directory if present
load_dotenv(ROOT_DIR / ".env")
load_dotenv(ROOT_DIR / "backend" / ".env")


class Settings(BaseSettings):
    # App
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    USE_MOCK_THREAT_INTEL: bool = os.getenv("USE_MOCK_THREAT_INTEL", "true").lower() in ("true", "1", "yes")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tracemail-sih-2026-super-secret-key-32chars")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "tracemail-jwt-secret-key-production-ready")
    
    # Database (Defaults to SQLite for instant local zero-dependency execution, or PostgreSQL if configured)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{ROOT_DIR / 'tracemail.db'}"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://localhost:8001",
    ]
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    IPINFO_API_KEY: str = os.getenv("IPINFO_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # Service Endpoints
    THREAT_SERVICE_URL: str = os.getenv("THREAT_SERVICE_URL", "http://localhost:8001")
    AI_SERVICE_URL: str = os.getenv("AI_SERVICE_URL", "http://localhost:8002")
    MAPS_SERVICE_URL: str = os.getenv("MAPS_SERVICE_URL", "http://localhost:8003")
    REPORTS_SERVICE_URL: str = os.getenv("REPORTS_SERVICE_URL", "http://localhost:8004")

    # Google Maps Platform Configuration (SIH 2026)
    GOOGLE_MAPS_API_KEY: str = os.getenv("GOOGLE_MAPS_API_KEY", "")
    GOOGLE_GEOCODING_URL: str = os.getenv("GOOGLE_GEOCODING_URL", "https://maps.googleapis.com/maps/api/geocode/json")
    GOOGLE_DIRECTIONS_URL: str = os.getenv("GOOGLE_DIRECTIONS_URL", "https://maps.googleapis.com/maps/api/directions/json")
    GOOGLE_PLACES_URL: str = os.getenv("GOOGLE_PLACES_URL", "https://maps.googleapis.com/maps/api/place/nearbysearch/json")
    IP_API_URL: str = os.getenv("IP_API_URL", "http://ip-api.com/json")

    # Google OAuth 2.0 & Gmail API Configuration
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:3000/inbox")

    class Config:
        case_sensitive = True
        extra = "allow"


settings = Settings()
