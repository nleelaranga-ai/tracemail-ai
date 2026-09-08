"""
TraceMail AI Backend — Cache Service
"""
from typing import Optional, Any
from backend.database.redis import cache_client
from backend.utils.constants import (
    CACHE_TTL_IP,
    CACHE_TTL_URL,
    CACHE_TTL_WHOIS,
    CACHE_TTL_GEO
)


class CacheService:
    @staticmethod
    def get_ip_reputation(ip: str) -> Optional[Any]:
        return cache_client.get(f"threat:ip:{ip}")

    @staticmethod
    def set_ip_reputation(ip: str, data: Any) -> bool:
        return cache_client.set(f"threat:ip:{ip}", data, ttl_seconds=CACHE_TTL_IP)

    @staticmethod
    def get_url_reputation(url: str) -> Optional[Any]:
        return cache_client.get(f"threat:url:{url}")

    @staticmethod
    def set_url_reputation(url: str, data: Any) -> bool:
        return cache_client.set(f"threat:url:{url}", data, ttl_seconds=CACHE_TTL_URL)

    @staticmethod
    def get_whois(domain: str) -> Optional[Any]:
        return cache_client.get(f"threat:whois:{domain}")

    @staticmethod
    def set_whois(domain: str, data: Any) -> bool:
        return cache_client.set(f"threat:whois:{domain}", data, ttl_seconds=CACHE_TTL_WHOIS)

    @staticmethod
    def get_geo(ip: str) -> Optional[Any]:
        return cache_client.get(f"threat:geo:{ip}")

    @staticmethod
    def set_geo(ip: str, data: Any) -> bool:
        return cache_client.set(f"threat:geo:{ip}", data, ttl_seconds=CACHE_TTL_GEO)
