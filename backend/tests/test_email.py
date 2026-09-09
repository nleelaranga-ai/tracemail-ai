"""
Unit tests for Email Parsing and Investigation Upload APIs
"""
import io
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

SAMPLE_EML_CONTENT = b"""From: PayPal Security <security@paypal-verification.com>
To: target@victim.org
Subject: Urgent: Verify your credentials now!
Date: Mon, 07 Sep 2026 12:00:00 +0000
Received: from mail.sketchy-relay.net (185.220.101.4) by mx.google.com
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Dear customer,

Your account has been locked. Click here immediately to restore access:
http://paypa1-secure.com/login

Thank you,
PayPal Security Team
"""


def test_email_parse_endpoint():
    file_payload = {"file": ("phish.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")}
    res = client.post("/api/v1/email/parse", files=file_payload)
    assert res.status_code == 200
    data = res.json()
    assert "paypal-verification.com" in data["sender"]
    assert "http://paypa1-secure.com/login" in data["extracted_urls"]
    assert "185.220.101.4" in data["extracted_ips"]
    assert data["headers"]["spf"] == "fail"


def test_create_investigation_endpoint():
    file_payload = {"file": ("phish.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")}
    res = client.post("/api/investigations", files=file_payload)
    assert res.status_code == 200
    data = res.json()
    assert "investigationId" in data
    assert data["status"] == "complete"
