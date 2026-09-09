"""
TraceMail AI — Shared Constants
Standardized system thresholds, ports, color codes, and API definitions.
"""

# Default Microservice Port Bindings
DEFAULT_BACKEND_PORT = 8000
DEFAULT_THREAT_INTEL_PORT = 8001
DEFAULT_AI_ENGINE_PORT = 8002
DEFAULT_FRONTEND_PORT = 3000
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_NEO4J_HTTP_PORT = 7474
DEFAULT_NEO4J_BOLT_PORT = 7687

# API Timeouts (seconds)
EXTERNAL_API_TIMEOUT_SECONDS = 5.0
WHOIS_TIMEOUT_SECONDS = 6.0
DNS_TIMEOUT_SECONDS = 4.0

# Risk Score Thresholds (0 - 100)
SCORE_SAFE_MAX = 29
SCORE_SUSPICIOUS_MAX = 69
SCORE_HIGH_MAX = 89
SCORE_CRITICAL_MIN = 90

# Threat Level Colors (Hex)
COLOR_SAFE = "#10B981"         # Tailwind Emerald-500
COLOR_SUSPICIOUS = "#F59E0B"   # Tailwind Amber-500
COLOR_HIGH = "#EF4444"         # Tailwind Red-500
COLOR_CRITICAL = "#7F1D1D"     # Tailwind Red-900

# Threat Level Colors (RGB)
COLOR_RGB_SAFE = (16, 185, 129)
COLOR_RGB_SUSPICIOUS = (245, 158, 11)
COLOR_RGB_HIGH = (239, 68, 68)
COLOR_RGB_CRITICAL = (127, 29, 29)

# Upstream Public API Endpoints
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
IPINFO_BASE_URL = "https://ipinfo.io"
IPAPI_BASE_URL = "https://ipapi.co"

# ISO 3166-1 Alpha-2 Common Country Names mapping
COUNTRY_CODE_MAP = {
    "US": "United States",
    "IN": "India",
    "DE": "Germany",
    "NL": "Netherlands",
    "RU": "Russia",
    "CN": "China",
    "GB": "United Kingdom",
    "FR": "France",
    "SG": "Singapore",
    "JP": "Japan",
    "BR": "Brazil",
    "CA": "Canada",
    "AU": "Australia",
}
