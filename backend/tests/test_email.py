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


INTERNSHALA_EML_CONTENT = b"""From: Internshala Team <student-support@internshala.com>
To: student@university.edu
Subject: New Internship Opportunities in Software Development
Date: Fri, 11 Sep 2026 08:00:00 +0530
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Dear Student,

Here are the latest internship opportunities matching your profile in Python and AI engineering.
Stipend: Rs. 25,000/month.
View opportunities and apply: https://internshala.com/internships/python-internship

Best regards,
Internshala Support
"""

BEC_SPOOFED_EML_CONTENT = b"""From: "PayPal Account Security" <security-alerts@scam-cloud-domain.xyz>
To: victim@company.com
Subject: URGENT: Immediate account suspension notice!
Date: Fri, 11 Sep 2026 09:15:00 +0000
Authentication-Results: spf=fail; dkim=fail

Attention:
Your account has been suspended due to unauthorized login attempts.
You must verify your password and confirm your identity within 24 hours.
Click here to login: http://paypa1-security-check.com/verify

Regards,
PayPal Team
"""


def test_internshala_legitimate_email_forensics():
    file_payload = {"file": ("internshala.eml", io.BytesIO(INTERNSHALA_EML_CONTENT), "message/rfc822")}
    res = client.post("/api/investigations", files=file_payload)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    # Retrieve detail
    detail_res = client.get(f"/api/investigations/{inv_id}")
    assert detail_res.status_code == 200
    data = detail_res.json()

    assert data["verdict"] == "safe"
    assert data["threat_score"] <= 30
    assert len(data["evidence_hash"]) == 64
    assert data["origin_city"] != "Frankfurt"
    assert any("verified" in act.lower() or "quarantine" not in act.lower() for act in data.get("action_items", []))

    # Check attack graph
    graph_res = client.get(f"/api/geo/graph/{inv_id}")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    sender_node = next(n for n in graph_data["nodes"] if n["id"] == "sender")
    assert sender_node["malicious"] is False


def test_display_name_spoofing_bec_forensics():
    file_payload = {"file": ("bec_phish.eml", io.BytesIO(BEC_SPOOFED_EML_CONTENT), "message/rfc822")}
    res = client.post("/api/investigations", files=file_payload)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    detail_res = client.get(f"/api/investigations/{inv_id}")
    assert detail_res.status_code == 200
    data = detail_res.json()

    assert data["verdict"] == "phishing"
    assert data["threat_score"] >= 70
    assert any("quarantine" in act.lower() for act in data.get("action_items", []))

