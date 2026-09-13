"""
TraceMail AI Backend — Narrative Consistency & Anti-Contradiction Tests
Asserts that threat intelligence, AI forensic narratives, and decision transparency
never contradict header authentication or threat scores.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.connection import SessionLocal
from backend.models.scan import Investigation
from backend.services.scan_service import ScanService
from backend.services.explainability_service import ExplainabilityService
from backend.utils.helpers import generate_uuid

client = TestClient(app)


@pytest.mark.asyncio
async def test_ai_engine_contradiction_prevention_on_spf_fail():
    """
    When an email claims a trusted domain (e.g. internshala.com) but fails SPF/DKIM,
    the AI engine MUST NOT claim 'Cryptographic SPF and DKIM signatures verified'
    or mark it as a verified legitimate safe email.
    """
    res = await ScanService.query_ai_engine(
        email_body="Hi candidate, your application for Cybersecurity Analyst Intern was reviewed.",
        sender="student-success@internshala.com",
        headers="Received: from mail.attacker-relay.com (185.220.101.4)\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail",
        auth_data={"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    )
    
    explanation = res.get("explanation", "").lower()
    reasons = [r.lower() for r in res.get("reasons", [])]
    
    # 1. Must not claim cryptographic pass
    assert "cryptographic spf and dkim signatures verified" not in explanation
    assert "cryptographic header authentication passes" not in explanation
    for r in reasons:
        assert "cryptographic alignment verified" not in r
        assert "cryptographic header authentication passes" not in r

    # 2. Must detect unauthorized relay / failure
    assert res.get("verdict") in ["phishing", "suspicious"]
    assert res.get("phishingScore") >= 35


def test_explainability_no_spf_pass_points_on_fail():
    """
    If an investigation has spf=fail, Explainability MUST NOT award
    'Cryptographic SPF Pass' points, even if the overall verdict was marked safe.
    """
    db = SessionLocal()
    try:
        inv_id = generate_uuid("inv_test_spf_fail_")
        inv = Investigation(
            id=inv_id,
            status="complete",
            sender="student-success@internshala.com",
            recipient="candidate@gmail.com",
            subject="Internship update",
            domain="internshala.com",
            phishing_score=20,
            verdict="safe",
            auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            dns={"spf": "fail", "dkim": "fail", "dmarc": "fail"}
        )
        db.add(inv)
        db.commit()

        exp = ExplainabilityService.get_explainability(inv_id, db)
        assert exp is not None
        reasons = exp.get("reasons", [])
        labels = [r["label"] for r in reasons]

        # Invariant: Must NOT contain passing labels
        assert "Cryptographic SPF Pass" not in labels
        assert "Valid DKIM Cryptographic Signature" not in labels

        # Should contain failure breakdown
        assert "SPF Authentication Failure" in labels
    finally:
        db.close()


def test_explainability_positive_pass_points_on_clean_pass():
    """
    When SPF and DKIM pass on a legitimate email, Explainability correctly awards
    positive transparency points.
    """
    db = SessionLocal()
    try:
        inv_id = generate_uuid("inv_test_spf_pass_")
        inv = Investigation(
            id=inv_id,
            status="complete",
            sender="student-success@internshala.com",
            recipient="candidate@gmail.com",
            subject="Internship update",
            domain="internshala.com",
            phishing_score=10,
            verdict="safe",
            auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            dns={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            whois={"domain_age_days": 5000, "registrar": "GoDaddy.com LLC"}
        )
        db.add(inv)
        db.commit()

        exp = ExplainabilityService.get_explainability(inv_id, db)
        assert exp is not None
        reasons = exp.get("reasons", [])
        labels = [r["label"] for r in reasons]

        assert "Cryptographic SPF Pass" in labels
        assert "Valid DKIM Cryptographic Signature" in labels
    finally:
        db.close()


def test_seeded_investigations_honest_provenance():
    """
    Seeded benchmark investigations must carry honest demo provenance metadata
    (mode='demo', provider_status='seeded', fallback_used=True) so the UI displays
    the purple 'Demo Benchmark' badge rather than masquerading as live external calls.
    """
    db = SessionLocal()
    try:
        cases = ["inv_paypal_phish_demo_01", "inv_internshala_demo_02", "inv_bec_wire_demo_03"]
        for cid in cases:
            inv = db.query(Investigation).filter(Investigation.id == cid).first()
            assert inv is not None, f"Seeded case {cid} missing from database"
            
            # DNS provenance
            assert inv.dns is not None, f"DNS missing on {cid}"
            assert inv.dns.get("mode") == "demo"
            assert inv.dns.get("provider_status") == "seeded"
            assert inv.dns.get("fallback_used") is True

            # WHOIS provenance
            assert inv.whois is not None, f"WHOIS missing on {cid}"
            assert inv.whois.get("mode") == "demo"
            assert inv.whois.get("provider_status") == "seeded"
            assert inv.whois.get("fallback_used") is True

            # Threat engines provenance
            for engine in [inv.abuse_ipdb, inv.virus_total, inv.urlscan, inv.google_safe_browsing]:
                assert engine is not None, f"Engine telemetry missing on {cid}"
                assert engine.get("mode") == "demo"
                assert engine.get("provider_status") == "seeded"
    finally:
        db.close()
