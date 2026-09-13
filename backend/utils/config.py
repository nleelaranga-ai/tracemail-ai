"""
TraceMail AI Backend — Configuration Loader
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import model_validator
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
# Automatically load .env from root or backend directory if present
load_dotenv(ROOT_DIR / ".env")
load_dotenv(ROOT_DIR / "backend" / ".env")


def resolve_database_url() -> str:
    url = (
        os.getenv("DATABASE_URL")
        or os.getenv("DATABASE_PUBLIC_URL")
        or os.getenv("POSTGRES_URL")
    )
    env = os.getenv("ENVIRONMENT", os.getenv("APP_ENV", "development")).lower()
    if not url:
        if env in ("production", "prod"):
            raise ValueError(
                "CRITICAL PRODUCTION SAFETY ERROR: DATABASE_URL environment variable is required in production! "
                "Cannot silently fall back to SQLite in production. Set DATABASE_URL in your Railway dashboard."
            )
        return f"sqlite:///{ROOT_DIR / 'tracemail.db'}"
    return url


def resolve_environment() -> str:
    env = os.getenv("ENVIRONMENT") or os.getenv("APP_ENV")
    if env:
        return env
    railway_env = os.getenv("RAILWAY_ENVIRONMENT_NAME") or os.getenv("RAILWAY_ENVIRONMENT")
    if railway_env:
        return railway_env
    if os.getenv("RAILWAY_SERVICE_ID") or os.getenv("RAILWAY_DEPLOYMENT_ID") or os.getenv("RAILWAY_PROJECT_ID"):
        return "production"
    db_url = os.getenv("DATABASE_URL", "")
    if "postgres" in db_url or "supabase" in db_url or "railway" in db_url:
        return "production"
    return "production"


def resolve_enable_demo_seed() -> str:
    val = os.getenv("ENABLE_DEMO_SEED")
    if val is not None:
        return val.lower()
    env = resolve_environment().lower()
    return "false" if env in ("production", "prod") else "true"


def resolve_use_mock_threat_intel() -> bool:
    env = resolve_environment().lower()
    has_live_keys = bool(
        os.getenv("VIRUSTOTAL_API_KEY")
        or os.getenv("ABUSEIPDB_API_KEY")
        or os.getenv("IPINFO_API_KEY")
    )
    if env in ("production", "prod") or has_live_keys:
        return False
    val = os.getenv("USE_MOCK_THREAT_INTEL")
    if val is not None:
        return val.lower() in ("true", "1", "yes")
    return False


class Settings(BaseSettings):
    # App
    ENVIRONMENT: str = resolve_environment()
    USE_MOCK_THREAT_INTEL: bool = resolve_use_mock_threat_intel()
    ENABLE_DEMO_SEED: str = resolve_enable_demo_seed()
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tracemail-sih-2026-super-secret-key-32chars")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "tracemail-jwt-secret-key-production-ready")

    # Database (Requires PostgreSQL in production; allows SQLite for local testing)
    DATABASE_URL: str = resolve_database_url()
    DATABASE_PUBLIC_URL: str = os.getenv("DATABASE_PUBLIC_URL", "")
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
