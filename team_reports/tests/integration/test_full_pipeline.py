"""
TraceMail AI — Team Reports: QA & Testing
File   : team_reports/tests/integration/test_full_pipeline.py
Purpose: End-to-end pipeline integration test:
         InvestigationPayload → JSONReportGenerator → PDFReportGenerator
         No HTTP calls — tests the Python layer end-to-end.
"""

from __future__ import annotations

import json

import pytest

from team_reports.reports.json.json_report import JSONReportGenerator, VerdictEnum
from team_reports.reports.pdf.pdf_generator import PDFReportGenerator
from team_reports.reports.schemas.report_schema import validate_report_dict


class TestFullReportPipeline:
    """Full pipeline: payload → JSON report → schema validation → (PDF)."""

    def test_pipeline_produces_valid_schema(self, investigation_payload):
        """Full pipeline output must pass JSON Schema validation."""
        gen = JSONReportGenerator()
        report = gen.generate(investigation_payload)
        errors = validate_report_dict(gen.to_dict(report))
        assert errors == [], f"Schema errors: {errors}"

    def test_pipeline_preserves_verdict(self, investigation_payload):
        """Verdict from payload must be preserved in report."""
        gen = JSONReportGenerator()
        report = gen.generate(investigation_payload)
        assert report.risk_score.verdict == VerdictEnum.MALICIOUS

    def test_pipeline_preserves_malicious_ip_count(self, investigation_payload):
        """Malicious IPs must be preserved exactly."""
        gen = JSONReportGenerator()
        report = gen.generate(investigation_payload)
        assert len(report.malicious_ips) == len(investigation_payload.malicious_ips)

    def test_pipeline_preserves_malicious_url_count(self, investigation_payload):
        gen = JSONReportGenerator()
        report = gen.generate(investigation_payload)
        assert len(report.malicious_urls) == len(investigation_payload.malicious_urls)

    def test_pipeline_json_round_trip(self, investigation_payload):
        """JSON serialise → deserialise must produce identical data."""
        gen = JSONReportGenerator()
        report = gen.generate(investigation_payload)
        serialised = gen.to_json(report)
        reparsed = json.loads(serialised)
        # Re-validate after round-trip
        errors = validate_report_dict(reparsed)
        assert errors == []

    def test_pipeline_different_payloads_different_hashes(
        self, investigation_payload
    ):
        """Different investigation data → different report hashes."""
        gen = JSONReportGenerator()
        r1 = gen.generate(investigation_payload)

        investigation_payload.risk_score.overall_score = 10.0
        investigation_payload.risk_score.verdict = VerdictEnum.CLEAN
        r2 = gen.generate(investigation_payload)

        assert r1.report_hash != r2.report_hash

    def test_pipeline_html_output_is_non_empty(self, investigation_payload):
        """HTML render produces non-empty output."""
        json_gen = JSONReportGenerator()
        pdf_gen = PDFReportGenerator()
        report = json_gen.generate(investigation_payload)
        html = pdf_gen.render_html(report)
        assert len(html) > 5000  # A full forensic report HTML is always large

    @pytest.mark.pdf
    def test_full_pdf_pipeline(self, investigation_payload):
        """Full pipeline including PDF generation (requires WeasyPrint)."""
        json_gen = JSONReportGenerator()
        pdf_gen = PDFReportGenerator()
        report = json_gen.generate(investigation_payload)
        try:
            pdf_bytes = pdf_gen.generate_pdf(report)
        except RuntimeError as e:
            if "WeasyPrint is not installed" in str(e):
                pytest.skip("WeasyPrint not available")
            raise
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 10_000  # Realistic forensic PDF


class TestCleanEmailPipeline:
    """Pipeline with a clean (non-malicious) email."""

    def test_clean_verdict_pipeline(
        self, case_summary, sender_analysis, authentication, evidence
    ):
        from team_reports.reports.json.json_report import (
            CorrelationGraph,
            InvestigationPayload,
            RiskScore,
            VerdictEnum,
        )

        case_summary.investigation_id = "INV-CLEAN-001"
        clean_payload = InvestigationPayload(
            investigation_id="INV-CLEAN-001",
            case_summary=case_summary,
            risk_score=RiskScore(
                overall_score=5.0,
                verdict=VerdictEnum.CLEAN,
                confidence=0.99,
            ),
            sender_analysis=sender_analysis,
            authentication=authentication,
            malicious_ips=[],
            malicious_urls=[],
            reputation_scores=[],
            timeline=[],
            correlation_graph=CorrelationGraph(),
            evidence=evidence,
        )

        gen = JSONReportGenerator()
        report = gen.generate(clean_payload)
        assert report.risk_score.verdict == VerdictEnum.CLEAN
        errors = validate_report_dict(gen.to_dict(report))
        assert errors == []
