"""
TraceMail AI — Threat Intelligence API Endpoint Contract Tests
Asserts that endpoints strictly return Section 6 Master API Contract schemas.
"""

try:
    import pytest
except ImportError:
    pytest = None
from fastapi.testclient import TestClient
from threat_intelligence.service import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "threat-intelligence"


def test_ip_threat_contract_endpoint():
    # Target: GET /api/threat/ip/{ip}
    resp = client.get("/api/threat/ip/185.220.101.4")
    assert resp.status_code == 200
    data = resp.json()

    # Exact contract assertions
    assert "ip" in data and data["ip"] == "185.220.101.4"
    assert "country" in data
    assert "city" in data
    assert "lat" in data and isinstance(data["lat"], float)
    assert "lon" in data and isinstance(data["lon"], float)
    assert "isp" in data
    assert "asn" in data
    assert "abuseScore" in data and 0 <= data["abuseScore"] <= 100
    assert "malicious" in data and isinstance(data["malicious"], bool)


def test_url_threat_contract_endpoint():
    # Target: POST /api/threat/url
    payload = {"url": "http://paypa1-secure.com/login"}
    resp = client.post("/api/threat/url", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["url"] == "http://paypa1-secure.com/login"
    assert "malicious" in data and isinstance(data["malicious"], bool)
    assert "category" in data
    assert "scanDate" in data
    assert "vtPositives" in data and isinstance(data["vtPositives"], int)
    assert "vtTotal" in data and isinstance(data["vtTotal"], int)


def test_auth_check_contract_endpoint():
    # Target: POST /api/threat/auth-check
    payload = {
        "rawHeaders": (
            "From: PayPal Support <support@paypal.com>\r\n"
            "Return-Path: <attacker@paypa1-secure.com>\r\n"
            "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        )
    }
    resp = client.post("/api/threat/auth-check", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["spf"] == "fail"
    assert data["dkim"] == "fail"
    assert data["dmarc"] == "fail"
    assert "domainAge" in data
    assert "registrar" in data
