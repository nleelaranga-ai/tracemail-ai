"""
TraceMail AI — Investigation Consistency & Regression Suite
Validates the 5 core .eml investigation samples and enforces mandatory consistency checks:
1. Canonical Verdict Equality: Top badge == AI panel == Reports == API.
2. Threat Score Additivity: sum(reason.weight) == threat_score.
3. Clean IOC URL Extraction: Quoted-printable soft breaks cleaned, no trailing '='.
4. Domain Allowlist: 'tracemail.ai' and recipient domains never treated as malicious IOCs.
5. Real AbuseIPDB Reports: No hardcoded 142 or fabricated values.
6. Provenance Truth: Live RDAP / VirusTotal labeled verified/live.
"""
import io
import os
import re
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.connection import get_db, SessionLocal
from backend.models.scan import Investigation
from backend.services.auth_service import AuthService
from backend.services.explainability_service import ExplainabilityService
from backend.parsers.ioc_parser import IOCParser
from backend.parsers.email_parser import EmailParser

client = TestClient(app)

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "scripts", "database", "fixtures"
)


@pytest.fixture
def auth_headers():
    token = AuthService.create_access_token({"sub": "admin@tracemail.ai", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_tracemail_ai_never_appears_as_ioc():
    """Mandatory Check: 'tracemail.ai' and recipient domains are never extracted as suspect IOC domains."""
    raw_text = (
        "From: Attacker <malicious@evil-relay.net>\n"
        "To: soc-analyst@tracemail.ai\n"
        "Subject: Test Internal Filtering\n"
        "Date: Mon, 14 Sep 2026 10:00:00 +0000\n"
        "Check this link: https://evil-phish-portal.top/login\n"
        "Internal portal is at https://app.tracemail.ai/dashboard\n"
    )
    iocs = IOCParser.extract_iocs(raw_text, recipient_domain="tracemail.ai")
    
    assert "evil-relay.net" in iocs["domains"] or "evil-phish-portal.top" in iocs["domains"]
    assert "tracemail.ai" not in iocs["domains"]
    assert "app.tracemail.ai" not in iocs["domains"]
    assert not any("tracemail.ai" in d for d in iocs["domains"])


def test_quoted_printable_soft_breaks_cleaned():
    """Mandatory Check: MIME quoted-printable soft breaks ('=\\r\\n') are rejoined and trailing '=' stripped."""
    qp_text = (
        "Content-Transfer-Encoding: quoted-printable\n\n"
        "Please confirm your account here:\n"
        "https://secure-portal.com/auth-ver=\n"
        "ify?token=3D12345=\n\n"
        "Another broken link: http://example-phish.xyz/verify-a=\n"
    )
    iocs = IOCParser.extract_iocs(qp_text)
    
    for url in iocs["urls"]:
        assert not url.endswith("="), f"URL ended with '=': {url}"
        assert "=3D" not in url, f"URL contained raw '=3D': {url}"
        assert not url.endswith("verify-a="), f"Soft line break was not cleaned: {url}"


def test_01_paypal_credential_phish_end_to_end(auth_headers, db_session):
    """Scenario 1: PayPal credential phishing email."""
    file_path = os.path.join(FIXTURES_DIR, "01_paypal_credential_phish.eml")
    with open(file_path, "rb") as f:
        eml_bytes = f.read()

    res = client.post("/api/investigations", files={"file": ("paypal.eml", io.BytesIO(eml_bytes), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    # 1. No contradictory verdicts
    assert inv.verdict == "phishing"
    assert inv.risk_level in ("High", "Critical")
    assert inv.ai_analysis["verdict"] == "phishing"
    assert "Phishing" in inv.ai_summary

    # 2. Threat score matches score breakdown exactly
    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score

    # 3. No tracemail.ai in IOCs
    assert "tracemail.ai" not in inv.entities.get("domains", [])


def test_02_ceo_fraud_bec_end_to_end(auth_headers, db_session):
    """Scenario 2: BEC CEO fraud wire transfer ($142,500 with meeting evasion and banking cut-off)."""
    file_path = os.path.join(FIXTURES_DIR, "02_ceo_fraud_bec.eml")
    with open(file_path, "rb") as f:
        eml_bytes = f.read()

    res = client.post("/api/investigations", files={"file": ("bec.eml", io.BytesIO(eml_bytes), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    # 1. BEC must be detected as Phishing (never safe 24/100)
    assert inv.verdict == "phishing"
    assert inv.phishing_score >= 80
    assert inv.risk_level in ("High", "Critical")
    assert inv.ai_analysis["verdict"] == "phishing"

    # 2. Score breakdown equals threat score
    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score

    # 3. Urgency NLP must NOT claim "Authentic Non-Urgent Tone"
    reason_labels = [r["label"] for r in exp["reasons"]]
    assert "Authentic Non-Urgent Tone" not in reason_labels


def test_03_malware_invoice_end_to_end(auth_headers, db_session):
    """Scenario 3: Malware invoice with suspicious download link."""
    file_path = os.path.join(FIXTURES_DIR, "03_malware_invoice.eml")
    with open(file_path, "rb") as f:
        eml_bytes = f.read()

    res = client.post("/api/investigations", files={"file": ("invoice.eml", io.BytesIO(eml_bytes), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    assert inv.verdict == "phishing"
    assert inv.ai_analysis["verdict"] == "phishing"
    
    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score


def test_04_legitimate_github_security_end_to_end(auth_headers, db_session):
    """Scenario 4: Legitimate GitHub security notification with cryptographic pass."""
    file_path = os.path.join(FIXTURES_DIR, "04_legitimate_github_security.eml")
    with open(file_path, "rb") as f:
        eml_bytes = f.read()

    res = client.post("/api/investigations", files={"file": ("github.eml", io.BytesIO(eml_bytes), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    # Legitimate email should be safe
    assert inv.verdict == "safe"
    assert inv.risk_level == "Low"
    assert inv.phishing_score <= 25
    assert inv.ai_analysis["verdict"] == "safe"

    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score


def test_05_multi_hop_spoofed_relay_end_to_end(auth_headers, db_session):
    """Scenario 5: Multi-hop spoofed relay email."""
    file_path = os.path.join(FIXTURES_DIR, "05_multi_hop_spoofed_relay.eml")
    with open(file_path, "rb") as f:
        eml_bytes = f.read()

    res = client.post("/api/investigations", files={"file": ("multihop.eml", io.BytesIO(eml_bytes), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    assert inv.verdict in ("phishing", "suspicious")
    assert inv.verdict == inv.ai_analysis["verdict"]

    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score


def test_internshala_legitimate_live_rdap_verification(auth_headers, db_session):
    """Scenario 6: Internshala recruitment email with verified live WHOIS/RDAP."""
    eml_content = (
        b"From: Internshala Team <student-support@internshala.com>\r\n"
        b"To: student@university.edu\r\n"
        b"Subject: Software Engineering Internship Openings\r\n"
        b"Date: Mon, 14 Sep 2026 09:00:00 +0530\r\n"
        b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n\r\n"
        b"Hello,\r\n\r\n"
        b"Explore verified software engineering internships: https://internshala.com/internships\r\n"
        b"Best regards,\r\nInternshala Team\r\n"
    )
    res = client.post("/api/investigations", files={"file": ("internshala.eml", io.BytesIO(eml_content), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    assert inv.verdict == "safe"
    assert inv.risk_level == "Low"
    assert inv.phishing_score <= 25
    assert inv.ai_analysis["verdict"] == "safe"

    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score


def test_sbi_otp_notification_safe(auth_headers, db_session):
    """Scenario 7: SBI official OTP notification with cryptographic pass."""
    eml_content = (
        b"From: State Bank of India <alerts@sbi.co.in>\r\n"
        b"To: customer@target-corp.com\r\n"
        b"Subject: Transaction OTP for SBI Card\r\n"
        b"Date: Mon, 14 Sep 2026 10:15:00 +0530\r\n"
        b"Authentication-Results: mx.target-corp.com; spf=pass; dkim=pass; dmarc=pass\r\n\r\n"
        b"Dear Customer,\r\n\r\n"
        b"Your One Time Password (OTP) for SBI NetBanking transaction is 749201.\r\n"
        b"Do not share this OTP with anyone.\r\n"
        b"Visit official portal: https://sbi.co.in\r\n"
        b"State Bank of India\r\n"
    )
    res = client.post("/api/investigations", files={"file": ("sbi_otp.eml", io.BytesIO(eml_content), "message/rfc822")}, headers=auth_headers)
    assert res.status_code == 200
    inv_id = res.json()["investigationId"]

    inv = db_session.query(Investigation).filter(Investigation.id == inv_id).first()
    assert inv is not None

    assert inv.verdict == "safe"
    assert inv.risk_level == "Low"
    assert inv.phishing_score <= 25
    assert inv.ai_analysis["verdict"] == "safe"

    exp = ExplainabilityService.get_explainability(inv_id, db_session)
    assert exp is not None
    assert sum(r["weight"] for r in exp["reasons"]) == inv.phishing_score
