"""
TraceMail AI — Resilient HTTP Client
Handles async outbound HTTP requests with timeouts, custom headers, and fallback error handling.
"""

import asyncio
import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional
from shared.config.logging import get_logger

logger = get_logger("ThreatHTTPClient")


async def async_http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """Perform non-blocking HTTP GET and return JSON response or None on failure."""
    def _sync_get():
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TraceMail-AI-ThreatIntel/1.0",
                **(headers or {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 201):
                    raw_data = resp.read().decode("utf-8")
                    return json.loads(raw_data)
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP GET {url} returned status {e.code}")
        except Exception as e:
            logger.debug(f"HTTP GET {url} failed: {e}")
        return None

    return await asyncio.to_thread(_sync_get)


async def async_http_post(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """Perform non-blocking HTTP POST with JSON body and return JSON response."""
    def _sync_post():
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TraceMail-AI-ThreatIntel/1.0",
                **(headers or {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 201):
                    raw_data = resp.read().decode("utf-8")
                    return json.loads(raw_data)
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP POST {url} returned status {e.code}")
        except Exception as e:
            logger.debug(f"HTTP POST {url} failed: {e}")
        return None

    return await asyncio.to_thread(_sync_post)
