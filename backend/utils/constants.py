"""
TraceMail AI Backend — Global Constants
"""

API_V1_STR = "/api/v1"
PROJECT_NAME = "TraceMail AI Backend"
VERSION = "1.0.0"

# JWT Config
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Threat Scoring Thresholds
SCORE_SAFE_MAX = 29
SCORE_SUSPICIOUS_MAX = 69
SCORE_HIGH_MAX = 89

# Cache TTLs (seconds)
CACHE_TTL_IP = 86400        # 24 hours
CACHE_TTL_URL = 86400       # 24 hours
CACHE_TTL_WHOIS = 604800    # 7 days
CACHE_TTL_GEO = 2592000     # 30 days

# Max file upload size (10 MB)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Default Downstream Service URLs
DEFAULT_THREAT_SERVICE_URL = "http://localhost:8001"
DEFAULT_AI_SERVICE_URL = "http://localhost:8002"
DEFAULT_MAPS_SERVICE_URL = "http://localhost:8003"
DEFAULT_REPORTS_SERVICE_URL = "http://localhost:8004"
