"""
TraceMail AI — Threat Engine Submodules Unit Tests
Verifies all 8 cybersecurity submodules and scoring mechanics.
"""

try:
    import pytest
except ImportError:
    class _DummyMark:
        @staticmethod
        def asyncio(f):
            return f
    class _DummyPytest:
        mark = _DummyMark()
    pytest = _DummyPytest()
import asyncio
from threat_intelligence.virustotal.vt_client import vt_client
from threat_intelligence.abuseipdb.abuse_client import abuse_client
from threat_intelligence.dns.auth_check import dns_checker
from threat_intelligence.whois.whois_client import whois_client
from threat_intelligence.urlscan.urlscan_client import urlscan_client
from threat_intelligence.geo.geo_client import geo_client
from threat_intelligence.indicators.extractor import ioc_extractor, defang_url, refang_url
from threat_intelligence.reputation.scorer import reputation_scorer
from shared.interfaces.contracts import AuthCheckResponse, IPThreatResponse, URLThreatResponse


@pytest.mark.asyncio
async def test_virustotal_client():
    # Phishing lookalike URL
    res = await vt_client.scan_url("http://paypa1-secure.com/login")
    assert res.url == "http://paypa1-secure.com/login"
    assert res.malicious is True
    assert res.category in ("phishing", "suspicious", "malware")
    assert res.vtPositives > 0

    # Clean URL
    res_clean = await vt_client.scan_url("https://example.com")
    assert res_clean.malicious is False
    assert res_clean.category == "clean"


@pytest.mark.asyncio
async def test_abuseipdb_client():
    # Known malicious IP
    res = await abuse_client.check_ip("185.220.101.4")
    assert res["abuseScore"] >= 80
    assert res["isMalicious"] is True

    # Benign IP (Google DNS)
    res_clean = await abuse_client.check_ip("8.8.8.8")
    assert res_clean["abuseScore"] == 0
    assert res_clean["isMalicious"] is False

    # Private IP
    res_priv = await abuse_client.check_ip("192.168.1.1")
    assert res_priv["isMalicious"] is False


@pytest.mark.asyncio
async def test_geo_client():
    # Known IP contract test: 185.220.101.4 -> Germany, Frankfurt, M247 Ltd
    resp = await geo_client.get_ip_threat("185.220.101.4")
    assert resp.ip == "185.220.101.4"
    assert resp.country == "Germany"
    assert resp.city == "Frankfurt"
    assert resp.isp == "M247 Ltd"
    assert resp.asn == "AS9009"
    assert resp.abuseScore >= 80
    assert resp.malicious is True


@pytest.mark.asyncio
async def test_whois_client():
    res = await whois_client.lookup_domain("paypa1-secure.com")
    assert "days" in res["domainAge"]
    assert res["registrar"] == "NameCheap Inc."


@pytest.mark.asyncio
async def test_dns_auth_checker():
    raw_headers = (
        "From: PayPal Support <support@paypal.com>\r\n"
        "Return-Path: <attacker@paypa1-secure.com>\r\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Received: from mail.sketchy-relay.net (185.220.101.4) by mx.google.com\r\n"
    )
    auth = await dns_checker.check_authentication(raw_headers)
    assert auth.spf == "fail"
    assert auth.dkim == "fail"
    assert auth.dmarc == "fail"
    assert auth.domainAge != "Unknown"


def test_ioc_extractor():
    text = (
        "Urgent: verify your account at hxxp://paypa1-secure[.]com/login.\n"
        "Sender relay was 185.220.101.4, internal hop 192.168.1.5.\n"
        "Contact admin at security-alert@paypa1-secure.com.\n"
        "MD5 payload hash: e4d909c290d0fb1ca068ffaddf22cbd0."
    )
    iocs = ioc_extractor.extract_all(text)
    assert "185.220.101.4" in iocs["public_ips"]
    assert "http://paypa1-secure.com/login" in iocs["urls"]
    assert "paypa1-secure.com" in iocs["domains"]
    assert "security-alert@paypa1-secure.com" in iocs["emails"]
    assert "e4d909c290d0fb1ca068ffaddf22cbd0" in iocs["hashes"]


def test_reputation_scorer():
    auth = AuthCheckResponse(
        spf="fail",
        dkim="fail",
        dmarc="fail",
        domainAge="12 days",
        registrar="NameCheap Inc.",
    )
    ip_threat = IPThreatResponse(
        ip="185.220.101.4",
        country="Germany",
        city="Frankfurt",
        lat=50.1109,
        lon=8.6821,
        isp="M247 Ltd",
        asn="AS9009",
        abuseScore=98,
        malicious=True,
    )
    url_threat = URLThreatResponse(
        url="http://paypa1-secure.com/login",
        malicious=True,
        category="phishing",
        scanDate="2026-09-06T10:00:00Z",
        vtPositives=14,
        vtTotal=90,
    )

    report = reputation_scorer.calculate_composite_report(
        auth_check=auth,
        ip_threats=[ip_threat],
        url_threats=[url_threat],
        sender_mismatch=True,
    )

    # Must match the integration specification contract
    assert report.risk_level in ("HIGH", "CRITICAL")
    assert report.risk_score >= 85
    assert report.malicious_url is True
    assert report.domain_age_days == 12
    assert report.ip_reputation == 98
    assert report.country == "Germany"
    assert report.spf == "FAIL"
    assert report.dmarc == "FAIL"
