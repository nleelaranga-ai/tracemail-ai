"""
TraceMail AI — Configuration & Settings
Loads environment variables, API keys, database URLs, and port configurations.
"""

import os
from functools import lru_cache
from typing import Optional
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Global system configuration model."""

    # App Environment
    APP_NAME: str = "TraceMail AI"
    APP_ENV: str = Field(default="development", description="development | staging | production")
    DEBUG: bool = Field(default=True)
    LOG_LEVEL: str = Field(default="INFO")

    # Service Ports
    BACKEND_PORT: int = 8000
    THREAT_INTEL_PORT: int = 8001
    AI_ENGINE_PORT: int = 8002
    FRONTEND_PORT: int = 3000

    # Service Base URLs
    BACKEND_URL: str = "http://localhost:8000"
    THREAT_INTEL_URL: str = "http://localhost:8001"
    AI_ENGINE_URL: str = "http://localhost:8002"
    FRONTEND_URL: str = "http://localhost:3000"

    # Database
    DATABASE_URL: str = Field(
        default="postgresql://tracemail:tracemail_secret@localhost:5432/tracemail_db"
    )
    NEO4J_URI: str = Field(default="bolt://localhost:7687")
    NEO4J_USER: str = Field(default="neo4j")
    NEO4J_PASSWORD: str = Field(default="tracemail_neo4j")

    # Security & Auth
    JWT_SECRET: str = Field(default="tracemail-hackathon-jwt-secret-key-sih26106")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # External Threat Intelligence APIs (Optional during mock/testing)
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None)
    ABUSEIPDB_API_KEY: Optional[str] = Field(default=None)
    IPINFO_API_KEY: Optional[str] = Field(default=None)
    URLSCAN_API_KEY: Optional[str] = Field(default=None)
    GROQ_API_KEY: Optional[str] = Field(default=None)

    # Operational Flags
    USE_MOCK_THREAT_INTEL: bool = Field(
        default=True,
        description="Whether to use intelligent heuristic mock data if external API keys are missing or rate limited"
    )

    @classmethod
    def load_from_env(cls) -> "Settings":
        """Load settings from os.environ with fallback defaults."""
        return cls(
            APP_NAME=os.getenv("APP_NAME", "TraceMail AI"),
            APP_ENV=os.getenv("APP_ENV", "development"),
            DEBUG=os.getenv("DEBUG", "true").lower() in ("true", "1", "yes"),
            LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO"),
            BACKEND_PORT=int(os.getenv("BACKEND_PORT", "8000")),
            THREAT_INTEL_PORT=int(os.getenv("THREAT_INTEL_PORT", "8001")),
            AI_ENGINE_PORT=int(os.getenv("AI_ENGINE_PORT", "8002")),
            FRONTEND_PORT=int(os.getenv("FRONTEND_PORT", "3000")),
            BACKEND_URL=os.getenv("BACKEND_URL", "http://localhost:8000"),
            THREAT_INTEL_URL=os.getenv("THREAT_INTEL_URL", "http://localhost:8001"),
            AI_ENGINE_URL=os.getenv("AI_ENGINE_URL", "http://localhost:8002"),
            FRONTEND_URL=os.getenv("FRONTEND_URL", "http://localhost:3000"),
            DATABASE_URL=os.getenv("DATABASE_URL", "postgresql://tracemail:tracemail_secret@localhost:5432/tracemail_db"),
            NEO4J_URI=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            NEO4J_USER=os.getenv("NEO4J_USER", "neo4j"),
            NEO4J_PASSWORD=os.getenv("NEO4J_PASSWORD", "tracemail_neo4j"),
            JWT_SECRET=os.getenv("JWT_SECRET", "tracemail-hackathon-jwt-secret-key-sih26106"),
            VIRUSTOTAL_API_KEY=os.getenv("VIRUSTOTAL_API_KEY"),
            ABUSEIPDB_API_KEY=os.getenv("ABUSEIPDB_API_KEY"),
            IPINFO_API_KEY=os.getenv("IPINFO_API_KEY"),
            URLSCAN_API_KEY=os.getenv("URLSCAN_API_KEY"),
            GROQ_API_KEY=os.getenv("GROQ_API_KEY"),
            USE_MOCK_THREAT_INTEL=os.getenv("USE_MOCK_THREAT_INTEL", "true").lower() in ("true", "1", "yes"),
        )


@lru_cache()
def get_settings() -> Settings:
    """Cached singleton provider for system configuration."""
    return Settings.load_from_env()
