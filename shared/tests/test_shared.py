"""
TraceMail AI — Shared Layer Unit Tests
Verifies validation logic and Master API Contract serialization.
"""

try:
    import pytest
except ImportError:
    pytest = None
from shared.enums import RiskLevel, AuthVerdict, ThreatType
from shared.validation.validators import (
    is_valid_ip,
    is_public_ip,
    is_valid_domain,
    is_valid_url,
    is_valid_email,
    extract_email_domain,
    is_valid_hash,
)
from shared.interfaces.contracts import (
    IPThreatResponse,
    URLThreatResponse,
    AuthCheckResponse,
    UnifiedThreatReport,
)


def test_ip_validation():
    # Valid public IPs
    assert is_valid_ip("185.220.101.4") is True
    assert is_public_ip("185.220.101.4") is True
    assert is_valid_ip("8.8.8.8") is True
    assert is_public_ip("8.8.8.8") is True

    # Private / Loopback IPs (RFC 1918)
    assert is_valid_ip("192.168.1.1") is True
    assert is_public_ip("192.168.1.1") is False
    assert is_valid_ip("127.0.0.1") is True
    assert is_public_ip("127.0.0.1") is False
    assert is_valid_ip("10.0.0.5") is True
    assert is_public_ip("10.0.0.5") is False

    # Invalid IPs
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("not-an-ip") is False
    assert is_valid_ip("") is False


def test_domain_validation():
    assert is_valid_domain("paypa1-secure.com") is True
    assert is_valid_domain("sub.domain.co.uk") is True
    assert is_valid_domain("invalid_domain") is False
    assert is_valid_domain("") is False


def test_url_validation():
    assert is_valid_url("http://paypa1-secure.com/login") is True
    assert is_valid_url("https://secure.bank.com/account?ref=123") is True
    assert is_valid_url("javascript:alert(1)") is False
    assert is_valid_url("ftp://not-supported.com") is False


def test_email_validation():
    assert is_valid_email("support@paypal.com") is True
    assert is_valid_email("attacker@sketchy-relay.net") is True
    assert is_valid_email("invalid-email-address") is False
    assert extract_email_domain("support@paypal.com") == "paypal.com"


def test_hash_validation():
    valid_md5 = "e4d909c290d0fb1ca068ffaddf22cbd0"
    valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert is_valid_hash(valid_md5) == (True, "md5")
    assert is_valid_hash(valid_sha256) == (True, "sha256")
    assert is_valid_hash("short")[0] is False


def test_master_api_contracts_conformity():
    # IP Threat Contract
    ip_resp = IPThreatResponse(
        ip="185.220.101.4",
        country="Germany",
        city="Frankfurt",
        lat=50.1109,
        lon=8.6821,
        isp="M247 Ltd",
        asn="AS9009",
        abuseScore=92,
        malicious=True,
    )
    ip_dict = ip_resp.model_dump()
    assert ip_dict["ip"] == "185.220.101.4"
    assert ip_dict["abuseScore"] == 92
    assert ip_dict["malicious"] is True

    # URL Threat Contract
    url_resp = URLThreatResponse(
        url="http://paypa1-secure.com/login",
        malicious=True,
        category="phishing",
        scanDate="2026-09-06T10:00:00Z",
        vtPositives=14,
        vtTotal=90,
    )
    url_dict = url_resp.model_dump()
    assert url_dict["vtPositives"] == 14
    assert url_dict["malicious"] is True

    # Auth Check Contract
    auth_resp = AuthCheckResponse(
        spf="fail",
        dkim="fail",
        dmarc="fail",
        domainAge="14 days",
        registrar="NameCheap Inc.",
    )
    auth_dict = auth_resp.model_dump()
    assert auth_dict["spf"] == "fail"
    assert auth_dict["domainAge"] == "14 days"

    # Unified Threat Report
    report = UnifiedThreatReport(
        risk_level="HIGH",
        risk_score=94,
        malicious_url=True,
        domain_age_days=12,
        ip_reputation=98,
        country="Germany",
        spf="FAIL",
        dkim="PASS",
        dmarc="FAIL",
    )
    assert report.risk_score == 94
    assert report.malicious_url is True
