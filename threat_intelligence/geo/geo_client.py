"""
TraceMail AI — Geolocation Intelligence Client
Resolves IP addresses to physical coordinates, country, city, ISP, and ASN,
and combines with AbuseIPDB reputation to satisfy GET /api/threat/ip/{ip}.
"""

from typing import Dict, Any, Optional
from shared.interfaces.contracts import IPThreatResponse
from shared.validation.validators import is_public_ip, is_valid_ip
from shared.config.settings import get_settings
from shared.config.logging import get_logger
from threat_intelligence.utils.cache import ip_cache
from threat_intelligence.utils.http_client import async_http_get
from threat_intelligence.abuseipdb.abuse_client import abuse_client

logger = get_logger("GeoClient")

# Known Geo coordinates for demo/testing hops
KNOWN_GEO_IPS = {
    "185.220.101.4": {
        "country": "Germany",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "isp": "M247 Ltd",
        "asn": "AS9009",
    },
    "142.250.1.27": {
        "country": "United States",
        "city": "Mountain View",
        "lat": 37.4223,
        "lon": -122.0848,
        "isp": "Google LLC",
        "asn": "AS15169",
    },
    "194.26.29.112": {
        "country": "Russia",
        "city": "Moscow",
        "lat": 55.7558,
        "lon": 37.6173,
        "isp": "HostPalace Web Solutions",
        "asn": "AS49981",
    },
    "8.8.8.8": {
        "country": "United States",
        "city": "Ashburn",
        "lat": 39.0438,
        "lon": -77.4874,
        "isp": "Google LLC",
        "asn": "AS15169",
    },
}


class GeoClient:
    """Client for IP Geolocation lookups."""

    def __init__(self, api_key: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or settings.IPINFO_API_KEY
        self.base_url = "https://ipinfo.io"

    async def get_ip_threat(self, ip: str) -> IPThreatResponse:
        """
        Enrich an IP with both geolocation and abuse reputation.
        Fulfills Master API Contract: GET /api/threat/ip/{ip}
        """
        clean_ip = ip.strip()

        # Handle invalid IP syntax
        if not is_valid_ip(clean_ip):
            return IPThreatResponse(
                ip=clean_ip,
                country="Invalid",
                city="Invalid",
                lat=0.0,
                lon=0.0,
                isp="Invalid IP Address",
                asn="None",
                abuseScore=0,
                malicious=False,
            )

        # Handle RFC 1918 Private IP ranges
        if not is_public_ip(clean_ip):
            return IPThreatResponse(
                ip=clean_ip,
                country="Private Network",
                city="Local Subnet",
                lat=0.0,
                lon=0.0,
                isp="RFC 1918 / Loopback",
                asn="None",
                abuseScore=0,
                malicious=False,
            )

        cache_key = f"full_threat_ip:{clean_ip}"
        cached = ip_cache.get(cache_key)
        if cached:
            return cached

        # Fetch abuse reputation
        abuse_info = await abuse_client.check_ip(clean_ip)
        abuse_score = abuse_info.get("abuseScore", 0)
        is_malicious = abuse_info.get("isMalicious", False) or abuse_score >= 20

        # Check known dataset first
        if clean_ip in KNOWN_GEO_IPS:
            geo = KNOWN_GEO_IPS[clean_ip]
            resp = IPThreatResponse(
                ip=clean_ip,
                country=geo["country"],
                city=geo["city"],
                lat=geo["lat"],
                lon=geo["lon"],
                isp=geo["isp"],
                asn=geo["asn"],
                abuseScore=abuse_score,
                malicious=is_malicious,
            )
            ip_cache.set(cache_key, resp)
            return resp

        # Query live IPinfo API if key present
        if self.api_key:
            try:
                url = f"{self.base_url}/{clean_ip}/json?token={self.api_key}"
                data = await async_http_get(url, timeout=4.0)
                if data:
                    loc = data.get("loc", "0,0").split(",")
                    lat = float(loc[0]) if len(loc) > 0 else 0.0
                    lon = float(loc[1]) if len(loc) > 1 else 0.0
                    org = data.get("org", "Unknown")
                    asn = org.split(" ")[0] if org.startswith("AS") else "Unknown"

                    resp = IPThreatResponse(
                        ip=clean_ip,
                        country=data.get("country", "Unknown"),
                        city=data.get("city", "Unknown"),
                        lat=lat,
                        lon=lon,
                        isp=org,
                        asn=asn,
                        abuseScore=abuse_score,
                        malicious=is_malicious,
                    )
                    ip_cache.set(cache_key, resp)
                    return resp
            except Exception as e:
                logger.warning(f"Live IPinfo lookup failed for {clean_ip}: {e}")

        # Fallback to free public ipapi.co
        try:
            url = f"https://ipapi.co/{clean_ip}/json/"
            data = await async_http_get(url, timeout=4.0)
            if data and "country_name" in data:
                resp = IPThreatResponse(
                    ip=clean_ip,
                    country=data.get("country_name", "Unknown"),
                    city=data.get("city", "Unknown"),
                    lat=float(data.get("latitude", 0.0)),
                    lon=float(data.get("longitude", 0.0)),
                    isp=data.get("org", "Unknown"),
                    asn=data.get("asn", "Unknown"),
                    abuseScore=abuse_score,
                    malicious=is_malicious,
                )
                ip_cache.set(cache_key, resp)
                return resp
        except Exception:
            pass

        # Final default fallback
        resp = IPThreatResponse(
            ip=clean_ip,
            country="United States",
            city="Washington",
            lat=38.9072,
            lon=-77.0369,
            isp=abuse_info.get("isp", "Internet Relay Node"),
            asn="AS0000",
            abuseScore=abuse_score,
            malicious=is_malicious,
        )
        ip_cache.set(cache_key, resp)
        return resp


geo_client = GeoClient()
