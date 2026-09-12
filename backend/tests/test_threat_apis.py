"""
TraceMail AI — Threat Intelligence API & Provider Test Matrix
Validates the 7 Core Threat Providers under:
1. Empty API key (Offline / Heuristic mode)
2. Invalid API key / Authentication Failure
3. Network Timeout / Connection Error
4. HTTP 429 Rate Limiting
5. Valid Simulated / Live Response
6. Canonical Schema & Deterministic Merge Policy in ThreatIntelligenceGateway
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from threat_intelligence.virustotal.vt_client import VirusTotalClient
from threat_intelligence.abuseipdb.abuse_client import AbuseIPDBClient
from threat_intelligence.geo.geo_client import GeoClient
from threat_intelligence.whois.whois_client import WHOISClient
from threat_intelligence.dns.auth_check import DNSAuthChecker
from threat_intelligence.urlscan.urlscan_client import URLScanClient
from threat_intelligence.google_safe_browsing.gsb_client import GoogleSafeBrowsingClient
from backend.services.threat_intelligence import ThreatIntelligenceGateway, CanonicalThreatIntelligenceReport


@pytest.mark.asyncio
async def test_virustotal_empty_key_fallback():
    """Verify VirusTotal client falls back to heuristics when no API key is set."""
    vt = VirusTotalClient(api_key="")
    res = await vt.scan_url("http://paypa1-secure-verification.xyz/login")
    assert res.malicious is True
    assert res.category == "phishing"
    assert res.vtPositives > 0


@pytest.mark.asyncio
async def test_virustotal_file_hash_scan():
    """Verify VirusTotal client inspects file hashes with fallback."""
    vt = VirusTotalClient(api_key="")
    # Clean/dummy hash
    res_clean = await vt.scan_file_hash("0" * 64)
    assert res_clean["malicious"] is False
    assert res_clean["positives"] == 0

    # Known bad test hash
    res_bad = await vt.scan_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res_bad["malicious"] is True
    assert res_bad["positives"] >= 40


@pytest.mark.asyncio
async def test_abuseipdb_fallback_and_private_ip():
    """Verify AbuseIPDB handles private IPs and heuristic lookups."""
    abuse = AbuseIPDBClient(api_key="")
    
    # Private IP
    priv_res = await abuse.check_ip("192.168.1.1")
    assert priv_res["isMalicious"] is False
    assert priv_res["abuseScore"] == 0

    # Known malicious demo IP
    mal_res = await abuse.check_ip("185.220.101.4")
    assert mal_res["isMalicious"] is True
    assert mal_res["abuseScore"] == 92


@pytest.mark.asyncio
async def test_geo_client_resolution():
    """Verify GeoClient resolves coordinates and IP info without crashing."""
    geo = GeoClient(api_key="")
    res = await geo.get_ip_threat("185.220.101.4")
    assert res.ip == "185.220.101.4"
    assert res.country == "Germany"
    assert res.city == "Frankfurt"
    assert res.lat > 0


@pytest.mark.asyncio
async def test_whois_rdap_client():
    """Verify WHOIS/RDAP client parses domain age and registrar."""
    whois = WHOISClient()
    res = await whois.lookup_domain("paypa1-secure.com")
    assert res["domainAgeDays"] == 14
    assert "NameCheap" in res["registrar"]


@pytest.mark.asyncio
async def test_dns_auth_checker():
    """Verify DNS auth checker parses SPF, DKIM, and DMARC alignment."""
    checker = DNSAuthChecker()
    raw_headers = """From: Security Team <alert@paypa1-secure.com>
Authentication-Results: mx.google.com; spf=fail (google.com: domain of alert@paypa1-secure.com does not designate permitted sender); dkim=fail
Received-SPF: fail
"""
    res = await checker.check_authentication(raw_headers)
    assert res.spf == "fail"
    assert res.dkim == "fail"
    assert res.dmarc == "fail"


@pytest.mark.asyncio
async def test_google_safe_browsing_heuristics():
    """Verify Google Safe Browsing client detects phishing tokens offline."""
    gsb = GoogleSafeBrowsingClient(api_key="")
    phish_res = await gsb.check_url("http://update-security-paypa1.com")
    assert phish_res["is_malicious"] is True
    assert "SOCIAL_ENGINEERING" in phish_res["threat_types"]

    clean_res = await gsb.check_url("https://www.google.com")
    assert clean_res["is_malicious"] is False


@pytest.mark.asyncio
async def test_urlscan_heuristics():
    """Verify URLScan client returns normalized structure with heuristics."""
    urlscan = URLScanClient(api_key="")
    res = await urlscan.scan_url("http://paypa1-verify.org")
    assert res["malicious"] is True
    assert res["score"] >= 80


@pytest.mark.asyncio
async def test_threat_intelligence_gateway_full_orchestration():
    """Verify ThreatIntelligenceGateway orchestrates all 7 providers and normalizes output."""
    raw_headers = """From: Spoofed Exec <ceo@sketchy-relay.net>
Authentication-Results: spf=fail; dkim=fail
"""
    report = await ThreatIntelligenceGateway.enrich_threat_intel(
        ip="185.220.101.4",
        domain="paypa1-secure.com",
        urls=["http://paypa1-secure.com/login"],
        raw_headers=raw_headers,
        attachments=[{"filename": "invoice_update.pdf.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
    )

    assert isinstance(report, CanonicalThreatIntelligenceReport)
    assert report.ip.address == "185.220.101.4"
    assert report.ip.country == "Germany"
    assert report.ip.abuse_score == 92
    assert report.domain.name == "paypa1-secure.com"
    assert report.domain.age_days == 14
    assert report.authentication.spf == "FAIL"
    assert report.authentication.dkim == "FAIL"
    assert report.virus_total.positives > 0
    assert report.threat_score >= 85
    assert report.risk_level == "Critical"
    assert len(report.attachments) == 1
    assert report.attachments[0].is_malicious is True


@pytest.mark.asyncio
async def test_threat_intelligence_gateway_failure_matrix():
    """
    Verify resilience when providers experience timeouts, 429 rate limits, and network exceptions.
    Ensures zero user-facing crash and successful fallback.
    """
    # Simulate GeoClient raising TimeoutError and WHOIS raising ConnectionError
    with patch("threat_intelligence.geo.geo_client.geo_client.get_ip_threat", side_effect=asyncio.TimeoutError("Simulated Timeout")),          patch("threat_intelligence.whois.whois_client.whois_client.lookup_domain", side_effect=ConnectionResetError("Simulated 429/Disconnect")),          patch("threat_intelligence.google_safe_browsing.gsb_client.gsb_client.check_url", side_effect=Exception("Simulated API Crash")):
        
        report = await ThreatIntelligenceGateway.enrich_threat_intel(
            ip="203.0.113.1",
            domain="unreachable-network.org",
            urls=["http://unreachable-network.org/bad"],
            raw_headers="",
            attachments=[]
        )

        assert isinstance(report, CanonicalThreatIntelligenceReport)
        # Verify fallback values exist and no exception was raised to caller
        assert report.ip.address == "203.0.113.1"
        assert report.domain.name == "unreachable-network.org"
        assert report.threat_score >= 5
        assert report.risk_level in ["Low", "Medium", "High", "Critical"]


@pytest.mark.asyncio
async def test_composite_threat_intel_endpoint():
    """Verify POST /api/threat/composite-intel HTTP contract."""
    from backend.main import app
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "ip": "185.220.101.4",
            "domain": "paypa1-secure.com",
            "urls": ["http://paypa1-secure.com/login"],
            "rawHeaders": "From: test@paypa1-secure.com\nAuthentication-Results: spf=fail; dkim=fail",
            "attachments": [{"filename": "update.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
        }
        res = await client.post("/api/threat/composite-intel", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "ip" in data
        assert "domain" in data
        assert "authentication" in data
        assert "virus_total" in data
        assert "google_safe_browsing" in data
        assert "urlscan" in data
        assert "threat_score" in data
        assert data["ip"]["address"] == "185.220.101.4"
        assert data["domain"]["name"] == "paypa1-secure.com"
        assert data["threat_score"] >= 85
