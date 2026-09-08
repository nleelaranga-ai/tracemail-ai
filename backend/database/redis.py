"""
TraceMail AI Backend — Redis Caching Layer with In-Memory Fallback
"""
import time
from typing import Optional, Any
import json
from backend.utils.config import settings
from backend.utils.logger import logger

try:
    import redis
    _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=1.0)
    # Test connection
    _redis_client.ping()
    _HAS_REDIS = True
    logger.info("Connected to external Redis cache server.")
except Exception:
    _HAS_REDIS = False
    _redis_client = None
    logger.info("Redis server not available. Using high-performance in-memory cache fallback.")


class MemoryCache:
    def __init__(self):
        self._store = {}

    def get(self, key: str) -> Optional[str]:
        if key in self._store:
            val, expire_at = self._store[key]
            if expire_at is None or expire_at > time.time():
                return val
            else:
                del self._store[key]
        return None

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        expire_at = time.time() + ex if ex else None
        self._store[key] = (value, expire_at)
        return True

    def delete(self, key: str) -> bool:
        if key in self._store:
            del self._store[key]
            return True
        return False


class CacheClient:
    def __init__(self):
        self.mem_cache = MemoryCache()

    def get(self, key: str) -> Optional[Any]:
        try:
            if _HAS_REDIS and _redis_client:
                data = _redis_client.get(key)
                if data:
                    return json.loads(data)
        except Exception:
            pass
        
        raw = self.mem_cache.get(key)
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                return raw
        return None

    def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> bool:
        val_str = json.dumps(value)
        try:
            if _HAS_REDIS and _redis_client:
                _redis_client.set(key, val_str, ex=ttl_seconds)
        except Exception:
            pass
        return self.mem_cache.set(key, val_str, ex=ttl_seconds)

    def delete(self, key: str) -> bool:
        try:
            if _HAS_REDIS and _redis_client:
                _redis_client.delete(key)
        except Exception:
            pass
        return self.mem_cache.delete(key)


cache_client = CacheClient()
