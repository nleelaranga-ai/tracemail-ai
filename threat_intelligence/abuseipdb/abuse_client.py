"""
TraceMail AI — AbuseIPDB Intelligence Client
Performs IP abuse confidence scoring and blacklist reputation lookups.
"""

from typing import Dict, Any, Optional
from shared.config.settings import get_settings
from shared.config.logging import get_logger
from shared.validation.validators import is_public_ip, is_valid_ip
from threat_intelligence.utils.cache import ip_cache
from threat_intelligence.utils.http_client import async_http_get

logger = get_logger("AbuseIPDBClient")

# Known mock malicious addresses for demo & testing
KNOWN_MALICIOUS_IPS = {
    "185.220.101.4": {"abuseScore": 92, "isp": "M247 Ltd", "country": "DE"},
    "194.26.29.112": {"abuseScore": 88, "isp": "HostPalace Web Solutions", "country": "RU"},
    "45.154.255.89": {"abuseScore": 95, "isp": "Chunghwa Telecom", "country": "NL"},
}


class AbuseIPDBClient:
    """Client for AbuseIPDB REST API v2."""

    def __init__(self, api_key: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP address reputation against AbuseIPDB.
        Returns: { abuseScore: int, isMalicious: bool, isp: str, countryCode: str, totalReports: int }
        """
        if not is_valid_ip(ip):
            return {"abuseScore": 0, "isMalicious": False, "isp": "Invalid IP", "countryCode": "XX", "totalReports": 0, "source": "validation", "mode": "fallback", "provider_status": "simulated", "fallback_used": True}

        if not is_public_ip(ip):
            return {"abuseScore": 0, "isMalicious": False, "isp": "Private/Local Network", "countryCode": "LOCAL", "totalReports": 0, "source": "rfc1918", "mode": "fallback", "provider_status": "simulated", "fallback_used": True}

        cache_key = f"abuseipdb:{ip}"
        cached = ip_cache.get(cache_key)
        if cached:
            return cached

        # Check live API if key is present
        if self.api_key:
            try:
                url = f"{self.base_url}/check?ipAddress={ip.strip()}&maxAgeInDays=90&verbose=true"
                headers = {"Key": self.api_key, "Accept": "application/json"}
                res = await async_http_get(url, headers=headers, timeout=5.0)

                if res and "data" in res:
                    data = res["data"]
                    score = int(data.get("abuseConfidenceScore", 0))
                    result = {
                        "abuseScore": score,
                        "isMalicious": score >= 20,
                        "isp": data.get("isp", "Unknown"),
                        "countryCode": data.get("countryCode", "Unknown"),
                        "totalReports": data.get("totalReports", 0),
                        "source": "abuseipdb_api",
                        "mode": "live",
                        "provider_status": "live",
                        "fallback_used": False,
                    }
                    ip_cache.set(cache_key, result)
                    return result
            except Exception as e:
                logger.warning(f"AbuseIPDB live API check failed for {ip}: {e}")

        # Fallback heuristic / known intelligence lookup
        result = self._heuristic_check(ip)
        ip_cache.set(cache_key, result)
        return result

    def _heuristic_check(self, ip: str) -> Dict[str, Any]:
        """Heuristic check for testing and offline execution."""
        clean_ip = ip.strip()
        if clean_ip in KNOWN_MALICIOUS_IPS:
            info = KNOWN_MALICIOUS_IPS[clean_ip]
            return {
                "abuseScore": info["abuseScore"],
                "isMalicious": True,
                "isp": info["isp"],
                "countryCode": info["country"],
                "totalReports": 42,
                "source": "known_threat_dataset",
                "mode": "fallback",
                "provider_status": "simulated",
                "fallback_used": True,
            }

        # Safe defaults for common public DNS
        if clean_ip in ("8.8.8.8", "8.8.4.4"):
            return {"abuseScore": 0, "isMalicious": False, "isp": "Google LLC", "countryCode": "US", "totalReports": 0, "source": "known_dns", "mode": "fallback", "provider_status": "simulated", "fallback_used": True}
        if clean_ip in ("1.1.1.1", "1.0.0.1"):
            return {"abuseScore": 0, "isMalicious": False, "isp": "Cloudflare, Inc.", "countryCode": "US", "totalReports": 0, "source": "known_dns", "mode": "fallback", "provider_status": "simulated", "fallback_used": True}

        return {
            "abuseScore": 0,
            "isMalicious": False,
            "isp": "Standard Internet Relay",
            "countryCode": "US",
            "totalReports": 0,
            "source": "heuristic",
            "mode": "fallback",
            "provider_status": "simulated",
            "fallback_used": True,
        }


abuse_client = AbuseIPDBClient()
