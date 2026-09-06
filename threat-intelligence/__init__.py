"""
TraceMail AI — Threat Intelligence Engine Root
"""

from threat_intelligence.virustotal.vt_client import vt_client, VirusTotalClient
from threat_intelligence.abuseipdb.abuse_client import abuse_client, AbuseIPDBClient
from threat_intelligence.dns.auth_check import dns_checker, DNSAuthChecker
from threat_intelligence.whois.whois_client import whois_client, WHOISClient
from threat_intelligence.urlscan.urlscan_client import urlscan_client, URLScanClient
from threat_intelligence.geo.geo_client import geo_client, GeoClient
from threat_intelligence.indicators.extractor import ioc_extractor, IOCExtractor
from threat_intelligence.reputation.scorer import reputation_scorer, ReputationScorer

__version__ = "1.0.0"
__all__ = [
    "vt_client",
    "VirusTotalClient",
    "abuse_client",
    "AbuseIPDBClient",
    "dns_checker",
    "DNSAuthChecker",
    "whois_client",
    "WHOISClient",
    "urlscan_client",
    "URLScanClient",
    "geo_client",
    "GeoClient",
    "ioc_extractor",
    "IOCExtractor",
    "reputation_scorer",
    "ReputationScorer",
]
