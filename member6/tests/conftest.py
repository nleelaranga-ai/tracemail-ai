"""
TraceMail AI — Member 6: QA & Testing
File   : member6/tests/conftest.py
Purpose: Shared pytest fixtures used across unit, integration, and
         contract test suites.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from member6.reports.json.json_report import (
    AuthenticationResults,
    AuthResultEnum,
    CaseSummary,
    CorrelationEdge,
    CorrelationGraph,
    CorrelationNode,
    GeoLocation,
    InvestigationEvidence,
    InvestigationPayload,
    JSONReport,
    JSONReportGenerator,
    MaliciousIP,
    MaliciousURL,
    ReputationScore,
    RiskScore,
    SenderAnalysis,
    ThreatTypeEnum,
    TimelineEvent,
    VerdictEnum,
)
from member6.reports.pdf.pdf_generator import PDFReportGenerator


# ---------------------------------------------------------------------------
# Reusable datetime helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 9, 8, 13, 0, 0, tzinfo=timezone.utc)
RECEIVED = datetime(2026, 9, 8, 12, 30, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Minimal valid sub-model fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def case_summary() -> CaseSummary:
    return CaseSummary(
        investigation_id="INV-TEST-001",
        subject="URGENT: Your account has been compromised",
        from_address="security@paypa1-alerts.com",
        to_addresses=["victim@company.com"],
        received_at=RECEIVED,
        analyzed_at=NOW,
        threat_type=ThreatTypeEnum.PHISHING,
        analyst_notes="Lookalike domain mimicking PayPal.",
    )


@pytest.fixture()
def risk_score() -> RiskScore:
    return RiskScore(
        overall_score=92.5,
        verdict=VerdictEnum.MALICIOUS,
        confidence=0.97,
        phishing_score=95.0,
        spoofing_score=88.0,
        malware_score=10.0,
        bec_score=20.0,
    )


@pytest.fixture()
def sender_analysis() -> SenderAnalysis:
    return SenderAnalysis(
        display_name="PayPal Security Team",
        email_address="security@paypa1-alerts.com",
        reply_to="harvest@evil-domain.ru",
        return_path="bounce@paypa1-alerts.com",
        sender_domain="paypa1-alerts.com",
        originating_ip="185.220.101.45",
        mail_server="mail.paypa1-alerts.com",
        domain_age_days=3,
        domain_registered="2026-09-05",
        is_free_email=False,
        is_newly_registered=True,
        lookalike_domain="paypal.com",
        header_from_mismatch=True,
    )


@pytest.fixture()
def authentication() -> AuthenticationResults:
    return AuthenticationResults(
        spf_result=AuthResultEnum.FAIL,
        spf_details="No matching SPF record",
        dkim_result=AuthResultEnum.FAIL,
        dkim_selector=None,
        dkim_domain=None,
        dmarc_result=AuthResultEnum.FAIL,
        dmarc_policy="reject",
        arc_result=AuthResultEnum.NONE,
        authentication_summary="SPF FAIL · DKIM FAIL · DMARC FAIL — email is not authenticated.",
    )


@pytest.fixture()
def malicious_ips() -> list[MaliciousIP]:
    geo = GeoLocation(
        ip="185.220.101.45",
        country="Russia",
        country_code="RU",
        region="Moscow",
        city="Moscow",
        latitude=55.7558,
        longitude=37.6176,
        isp="Unknown ISP",
        asn="AS1234",
        is_tor=True,
        is_vpn=False,
        is_proxy=False,
        is_datacenter=False,
    )
    return [
        MaliciousIP(
            ip="185.220.101.45",
            threat_score=96.0,
            threat_categories=["phishing", "spam", "tor-exit"],
            reputation_source=["AbuseIPDB", "Spamhaus", "AlienVault"],
            geo=geo,
            first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_seen=NOW,
            abuse_reports=142,
        )
    ]


@pytest.fixture()
def malicious_urls() -> list[MaliciousURL]:
    return [
        MaliciousURL(
            url="http://paypa1-alerts.com/secure/verify?token=abc123",
            domain="paypa1-alerts.com",
            threat_score=98.0,
            threat_categories=["phishing", "credential-harvesting"],
            redirect_chain=[
                "http://paypa1-alerts.com/secure/verify?token=abc123",
                "http://collect.evil.ru/form",
            ],
            final_destination="http://collect.evil.ru/form",
            is_phishing_kit=True,
            is_credential_harvester=True,
            reputation_sources=["VirusTotal", "PhishTank", "Google SafeBrowsing"],
        )
    ]


@pytest.fixture()
def reputation_scores() -> list[ReputationScore]:
    return [
        ReputationScore(
            entity="paypa1-alerts.com",
            entity_type="domain",
            score=97.0,
            sources=["VirusTotal", "AlienVault"],
            categories=["phishing"],
            last_checked=NOW,
            is_blacklisted=True,
            blacklist_count=8,
        )
    ]


@pytest.fixture()
def timeline() -> list[TimelineEvent]:
    return [
        TimelineEvent(
            timestamp=RECEIVED,
            event_type="RECEIVED",
            description="Email received by mail server",
            actor="mx1.company.com",
        ),
        TimelineEvent(
            timestamp=NOW,
            event_type="ANALYZED",
            description="Full AI-powered forensic analysis completed",
            actor="TraceMail AI Engine",
        ),
    ]


@pytest.fixture()
def correlation_graph() -> CorrelationGraph:
    nodes = [
        CorrelationNode(
            node_id="n1",
            node_type="email",
            label="security@paypa1-alerts.com",
            threat_score=92.5,
        ),
        CorrelationNode(
            node_id="n2",
            node_type="ip",
            label="185.220.101.45",
            threat_score=96.0,
        ),
        CorrelationNode(
            node_id="n3",
            node_type="domain",
            label="paypa1-alerts.com",
            threat_score=97.0,
        ),
    ]
    edges = [
        CorrelationEdge(
            source_id="n1",
            target_id="n2",
            relationship="SENDS_FROM",
            confidence=0.95,
        ),
        CorrelationEdge(
            source_id="n1",
            target_id="n3",
            relationship="BELONGS_TO",
            confidence=1.0,
        ),
    ]
    return CorrelationGraph(nodes=nodes, edges=edges)


@pytest.fixture()
def evidence() -> InvestigationEvidence:
    return InvestigationEvidence(
        raw_headers=(
            "From: PayPal Security Team <security@paypa1-alerts.com>\r\n"
            "To: victim@company.com\r\n"
            "Subject: URGENT: Your account has been compromised\r\n"
            "Date: Mon, 08 Sep 2026 12:30:00 +0000\r\n"
            "Received: from mail.paypa1-alerts.com (185.220.101.45)\r\n"
        ),
        parsed_headers={
            "from": "PayPal Security Team <security@paypa1-alerts.com>",
            "to": "victim@company.com",
            "subject": "URGENT: Your account has been compromised",
        },
        email_body_text="Dear Customer, Your account is at risk. Click here to verify.",
        email_body_html="<p>Dear Customer, <a href='http://paypa1-alerts.com/...'>Click here</a></p>",
        attachments=[],
        extracted_urls=["http://paypa1-alerts.com/secure/verify?token=abc123"],
        extracted_ips=["185.220.101.45"],
        hashes={
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    )


# ---------------------------------------------------------------------------
# Composite fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def investigation_payload(
    case_summary,
    risk_score,
    sender_analysis,
    authentication,
    malicious_ips,
    malicious_urls,
    reputation_scores,
    timeline,
    correlation_graph,
    evidence,
) -> InvestigationPayload:
    return InvestigationPayload(
        investigation_id="INV-TEST-001",
        case_summary=case_summary,
        risk_score=risk_score,
        sender_analysis=sender_analysis,
        authentication=authentication,
        malicious_ips=malicious_ips,
        malicious_urls=malicious_urls,
        reputation_scores=reputation_scores,
        timeline=timeline,
        correlation_graph=correlation_graph,
        evidence=evidence,
    )


@pytest.fixture()
def json_generator() -> JSONReportGenerator:
    return JSONReportGenerator()


@pytest.fixture()
def pdf_generator() -> PDFReportGenerator:
    return PDFReportGenerator()


@pytest.fixture()
def json_report(json_generator, investigation_payload) -> JSONReport:
    return json_generator.generate(investigation_payload)
