"""
TraceMail AI — Team Reports: QA & Testing
File   : team_reports/tests/unit/test_report_models.py
Purpose: Unit tests for all Pydantic report models — field validation,
         constraints, edge cases, and model consistency rules.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from team_reports.reports.json.json_report import (
    AuthResultEnum,
    AuthenticationResults,
    CaseSummary,
    CorrelationEdge,
    CorrelationGraph,
    CorrelationNode,
    GeoLocation,
    InvestigationEvidence,
    InvestigationPayload,
    JSONReport,
    MaliciousIP,
    MaliciousURL,
    ReputationScore,
    RiskScore,
    SenderAnalysis,
    ThreatTypeEnum,
    TimelineEvent,
    VerdictEnum,
)

NOW = datetime(2026, 9, 8, 13, 0, 0, tzinfo=timezone.utc)


class TestRiskScore:
    def test_valid_risk_score(self):
        rs = RiskScore(
            overall_score=75.0,
            verdict=VerdictEnum.SUSPICIOUS,
            confidence=0.85,
        )
        assert rs.overall_score == 75.0

    def test_score_rounded_to_2_decimals(self):
        rs = RiskScore(
            overall_score=75.123456,
            verdict=VerdictEnum.SUSPICIOUS,
            confidence=0.85,
        )
        assert rs.overall_score == 75.12

    def test_score_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            RiskScore(overall_score=-1.0, verdict=VerdictEnum.CLEAN, confidence=0.5)

    def test_score_above_100_rejected(self):
        with pytest.raises(ValidationError):
            RiskScore(overall_score=101.0, verdict=VerdictEnum.CLEAN, confidence=0.5)

    def test_confidence_above_1_rejected(self):
        with pytest.raises(ValidationError):
            RiskScore(overall_score=50.0, verdict=VerdictEnum.CLEAN, confidence=1.1)

    def test_all_verdict_enum_values_valid(self):
        for v in VerdictEnum:
            rs = RiskScore(overall_score=50.0, verdict=v, confidence=0.5)
            assert rs.verdict == v

    def test_default_sub_scores_are_zero(self):
        rs = RiskScore(
            overall_score=50.0, verdict=VerdictEnum.UNKNOWN, confidence=0.5
        )
        assert rs.phishing_score == 0.0
        assert rs.spoofing_score == 0.0
        assert rs.malware_score == 0.0
        assert rs.bec_score == 0.0


class TestCaseSummary:
    def test_valid_case_summary(self):
        cs = CaseSummary(
            investigation_id="INV-001",
            subject="Test Email",
            from_address="attacker@evil.com",
            to_addresses=["victim@corp.com"],
            received_at=NOW,
        )
        assert cs.investigation_id == "INV-001"

    def test_multiple_recipients(self):
        cs = CaseSummary(
            investigation_id="INV-002",
            subject="Bulk phish",
            from_address="attacker@evil.com",
            to_addresses=["a@b.com", "c@d.com", "e@f.com"],
            received_at=NOW,
        )
        assert len(cs.to_addresses) == 3

    def test_analyzed_at_defaults_to_now(self):
        cs = CaseSummary(
            investigation_id="INV-003",
            subject="Test",
            from_address="x@y.com",
            to_addresses=["z@w.com"],
            received_at=NOW,
        )
        assert cs.analyzed_at is not None
        assert cs.analyzed_at.tzinfo is not None

    def test_analyst_notes_optional(self):
        cs = CaseSummary(
            investigation_id="INV-004",
            subject="Test",
            from_address="x@y.com",
            to_addresses=["z@w.com"],
            received_at=NOW,
        )
        assert cs.analyst_notes is None


class TestAuthenticationResults:
    def test_all_pass(self):
        auth = AuthenticationResults(
            spf_result=AuthResultEnum.PASS,
            dkim_result=AuthResultEnum.PASS,
            dmarc_result=AuthResultEnum.PASS,
            authentication_summary="All pass",
        )
        assert auth.spf_result == AuthResultEnum.PASS

    def test_all_fail(self):
        auth = AuthenticationResults(
            spf_result=AuthResultEnum.FAIL,
            dkim_result=AuthResultEnum.FAIL,
            dmarc_result=AuthResultEnum.FAIL,
            authentication_summary="All fail",
        )
        assert auth.dmarc_result == AuthResultEnum.FAIL

    def test_arc_result_optional(self):
        auth = AuthenticationResults(
            spf_result=AuthResultEnum.PASS,
            dkim_result=AuthResultEnum.PASS,
            dmarc_result=AuthResultEnum.PASS,
            authentication_summary="Pass",
        )
        assert auth.arc_result is None

    def test_all_auth_enum_values(self):
        for result in AuthResultEnum:
            auth = AuthenticationResults(
                spf_result=result,
                dkim_result=result,
                dmarc_result=result,
                authentication_summary=f"Result: {result}",
            )
            assert auth.spf_result == result


class TestSenderAnalysis:
    def test_minimal_sender_analysis(self):
        sa = SenderAnalysis(
            display_name="Fake Sender",
            email_address="fake@evil.com",
            sender_domain="evil.com",
        )
        assert sa.display_name == "Fake Sender"

    def test_defaults(self):
        sa = SenderAnalysis(
            display_name="Test",
            email_address="test@test.com",
            sender_domain="test.com",
        )
        assert sa.is_free_email is False
        assert sa.is_newly_registered is False
        assert sa.header_from_mismatch is False
        assert sa.reply_to is None
        assert sa.return_path is None
        assert sa.lookalike_domain is None


class TestMaliciousIP:
    def test_valid_malicious_ip(self):
        ip = MaliciousIP(
            ip="1.2.3.4",
            threat_score=85.0,
        )
        assert ip.ip == "1.2.3.4"

    def test_threat_score_bounds(self):
        with pytest.raises(ValidationError):
            MaliciousIP(ip="1.2.3.4", threat_score=101.0)
        with pytest.raises(ValidationError):
            MaliciousIP(ip="1.2.3.4", threat_score=-1.0)

    def test_geo_optional(self):
        ip = MaliciousIP(ip="1.2.3.4", threat_score=50.0)
        assert ip.geo is None

    def test_with_geo(self):
        geo = GeoLocation(ip="1.2.3.4", country="Russia", country_code="RU")
        ip = MaliciousIP(ip="1.2.3.4", threat_score=80.0, geo=geo)
        assert ip.geo.country == "Russia"


class TestMaliciousURL:
    def test_valid_malicious_url(self):
        url = MaliciousURL(
            url="http://evil.com/phish",
            domain="evil.com",
            threat_score=90.0,
        )
        assert url.domain == "evil.com"

    def test_score_bounds(self):
        with pytest.raises(ValidationError):
            MaliciousURL(url="http://a.com", domain="a.com", threat_score=200.0)

    def test_phishing_flags_default_false(self):
        url = MaliciousURL(
            url="http://a.com", domain="a.com", threat_score=50.0
        )
        assert url.is_phishing_kit is False
        assert url.is_credential_harvester is False


class TestTimelineEvent:
    def test_valid_event(self):
        event = TimelineEvent(
            timestamp=NOW,
            event_type="RECEIVED",
            description="Email received",
        )
        assert event.event_type == "RECEIVED"

    def test_actor_optional(self):
        event = TimelineEvent(
            timestamp=NOW,
            event_type="ANALYZED",
            description="Analysis complete",
        )
        assert event.actor is None

    def test_metadata_defaults_empty(self):
        event = TimelineEvent(
            timestamp=NOW,
            event_type="BLOCKED",
            description="Blocked by filter",
        )
        assert event.metadata == {}


class TestCorrelationGraph:
    def test_empty_graph(self):
        g = CorrelationGraph()
        assert g.nodes == []
        assert g.edges == []

    def test_graph_with_nodes_and_edges(self):
        g = CorrelationGraph(
            nodes=[
                CorrelationNode(node_id="n1", node_type="email", label="a@b.com"),
                CorrelationNode(node_id="n2", node_type="ip", label="1.2.3.4"),
            ],
            edges=[
                CorrelationEdge(
                    source_id="n1",
                    target_id="n2",
                    relationship="SENDS_FROM",
                )
            ],
        )
        assert len(g.nodes) == 2
        assert len(g.edges) == 1


class TestInvestigationPayload:
    def test_id_mismatch_raises(
        self, case_summary, risk_score, sender_analysis,
        authentication, evidence
    ):
        """Payload raises if investigation_id doesn't match case_summary."""
        with pytest.raises(ValidationError):
            InvestigationPayload(
                investigation_id="DIFFERENT-ID",
                case_summary=case_summary,
                risk_score=risk_score,
                sender_analysis=sender_analysis,
                authentication=authentication,
                evidence=evidence,
            )

    def test_valid_payload_accepted(self, investigation_payload):
        assert investigation_payload.investigation_id == "INV-TEST-001"


class TestInvestigationEvidence:
    def test_hashes_field(self):
        ev = InvestigationEvidence(
            raw_headers="From: test@test.com",
            hashes={"sha256": "abc123"},
        )
        assert ev.hashes["sha256"] == "abc123"

    def test_empty_attachments_by_default(self):
        ev = InvestigationEvidence(raw_headers="")
        assert ev.attachments == []

    def test_extracted_urls_and_ips(self):
        ev = InvestigationEvidence(
            raw_headers="",
            extracted_urls=["http://a.com", "http://b.com"],
            extracted_ips=["1.2.3.4"],
        )
        assert len(ev.extracted_urls) == 2
        assert ev.extracted_ips[0] == "1.2.3.4"


class TestJSONReportIntegrity:
    def test_report_hash_changes_when_content_changes(
        self, json_generator, investigation_payload
    ):
        """Two reports with different data must have different hashes."""
        r1 = json_generator.generate(investigation_payload)

        investigation_payload.case_summary.subject = "MODIFIED SUBJECT"
        r2 = json_generator.generate(investigation_payload)

        assert r1.report_hash != r2.report_hash
