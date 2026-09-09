"""
Unit tests for Scan APIs (Email, URL, Domain)
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_scan_email_endpoint():
    payload = {
        "emailBody": "Click here to login and update your credentials: http://paypa1-secure.com/login",
        "headers": "From: Security <spoof@paypal.com>\nAuthentication-Results: spf=fail; dmarc=fail"
    }
    res = client.post("/api/v1/scan/email", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "phishingScore" in data
    assert data["verdict"] in ["phishing", "suspicious"]
    assert len(data["entities"]["urls"]) > 0


def test_scan_url_endpoint():
    res = client.post("/api/v1/scan/url", json={"url": "http://paypa1-secure.com/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["indicator"] == "http://paypa1-secure.com/login"
    assert data["is_malicious"] is True


def test_scan_domain_endpoint():
    res = client.post("/api/v1/scan/domain", json={"domain": "paypa1-secure.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "domain"
