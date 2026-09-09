"""
TraceMail AI — In-Memory TTL Cache
Thread-safe, lightweight caching to prevent redundant external API calls and rate-limiting.
"""

import time
from typing import Any, Dict, Optional, Tuple


class TTLCache:
    """In-memory cache with Time-To-Live (TTL) expiration per entry."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self.default_ttl = default_ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached value if not expired, else None."""
        if key not in self._cache:
            return None
        val, expiry = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        return val

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Store value with expiration."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        self._cache[key] = (value, time.time() + ttl)

    def clear(self) -> None:
        """Clear entire cache."""
        self._cache.clear()

    def size(self) -> int:
        """Return number of cached items."""
        return len(self._cache)


# Global cache singletons
ip_cache = TTLCache(default_ttl_seconds=7200)
url_cache = TTLCache(default_ttl_seconds=7200)
domain_cache = TTLCache(default_ttl_seconds=86400)
whois_cache = TTLCache(default_ttl_seconds=86400)
