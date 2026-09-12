"""
TraceMail AI — Google Safe Browsing v4 Intelligence Client
Checks URLs against Google's global phishing, malware, and social engineering threat lists.
Includes zero-failure error handling, strict timeouts, and offline heuristic fallbacks.
"""

from typing import Dict, Any, List, Optional
from shared.config.settings import get_settings
from shared.config.logging import get_logger
from threat_intelligence.utils.cache import url_cache
from threat_intelligence.utils.http_client import async_http_post

logger = get_logger("GoogleSafeBrowsingClient")

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]


class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing API v4."""

    def __init__(self, api_key: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None)
        self.endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing API.
        Returns normalized dictionary:
        {
            "is_malicious": bool,
            "threat_types": List[str],
            "matches_count": int,
            "provider": str,
            "source": str
        }
        """
        if not url or not isinstance(url, str):
            return self._clean_result("empty_input")

        clean_url = url.strip()
        cache_key = f"gsb:{clean_url}"
        cached = url_cache.get(cache_key)
        if cached:
            return cached

        # Check live API if key is present
        if self.api_key:
            try:
                request_url = f"{self.endpoint}?key={self.api_key}"
                payload = {
                    "client": {
                        "clientId": "tracemail-ai",
                        "clientVersion": "1.0.0"
                    },
                    "threatInfo": {
                        "threatTypes": THREAT_TYPES,
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": clean_url}]
                    }
                }

                data = await async_http_post(request_url, payload=payload, timeout=3.0)
                if data is not None:
                    matches = data.get("matches", [])
                    threat_types = list({m.get("threatType", "MALICIOUS") for m in matches})
                    is_malicious = len(matches) > 0
                    result = {
                        "is_malicious": is_malicious,
                        "threat_types": threat_types,
                        "matches_count": len(matches),
                        "provider": "Google Safe Browsing v4",
                        "source": "live"
                    }
                    url_cache.set(cache_key, result)
                    return result
            except Exception as e:
                logger.warning(f"Google Safe Browsing live query failed for {clean_url}: {e}")

        # Graceful heuristic fallback
        result = self._heuristic_check(clean_url)
        url_cache.set(cache_key, result)
        return result

    def _heuristic_check(self, url: str) -> Dict[str, Any]:
        """Offline pattern inspection when live API key is missing or unreachable."""
        url_lower = url.lower()
        phish_tokens = ["paypa1", "verify-account", "update-security", "login-auth", "secure-banking", "account-suspended", "000webhost", "ngrok-free"]
        is_phishing = any(tok in url_lower for tok in phish_tokens)
        
        malware_tokens = [".exe", ".scr", ".vbs", ".iso", ".bat"]
        is_malware = any(url_lower.endswith(tok) for tok in malware_tokens)

        threat_types = []
        if is_phishing:
            threat_types.append("SOCIAL_ENGINEERING")
        if is_malware:
            threat_types.append("MALWARE")

        is_malicious = bool(threat_types)
        return {
            "is_malicious": is_malicious,
            "threat_types": threat_types,
            "matches_count": len(threat_types),
            "provider": "Google Safe Browsing (Heuristic Fallback)",
            "source": "heuristic"
        }

    def _clean_result(self, reason: str = "clean") -> Dict[str, Any]:
        return {
            "is_malicious": False,
            "threat_types": [],
            "matches_count": 0,
            "provider": "Google Safe Browsing",
            "source": reason
        }


gsb_client = GoogleSafeBrowsingClient()
