"""
TraceMail AI — Team Reports: QA & Testing
File   : team_reports/tests/unit/test_json_generator.py
Purpose: Unit tests for JSONReportGenerator and JSONReport model.
"""

from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError

from team_reports.reports.json.json_report import (
    InvestigationPayload,
    JSONReport,
    RiskScore,
    VerdictEnum,
)
from team_reports.reports.schemas.report_schema import validate_report_dict


class TestJSONReportGenerator:
    """Tests for JSONReportGenerator.generate()"""

    def test_generates_report_from_valid_payload(self, json_generator, investigation_payload):
        """Generator produces a JSONReport from a valid InvestigationPayload."""
        report = json_generator.generate(investigation_payload)
        assert isinstance(report, JSONReport)

    def test_report_has_unique_report_id(self, json_generator, investigation_payload):
        """Each generated report gets a unique UUID report_id."""
        r1 = json_generator.generate(investigation_payload)
        r2 = json_generator.generate(investigation_payload)
        assert r1.report_id != r2.report_id
        # Both should be valid UUIDs
        uuid.UUID(r1.report_id)
        uuid.UUID(r2.report_id)

    def test_report_inherits_investigation_id(self, json_generator, investigation_payload):
        """report.investigation_id must match the payload."""
        report = json_generator.generate(investigation_payload)
        assert report.investigation_id == investigation_payload.investigation_id

    def test_report_has_integrity_hash(self, json_generator, investigation_payload):
        """Generated report must include a non-empty SHA-256 hash."""
        report = json_generator.generate(investigation_payload)
        assert report.report_hash
        assert len(report.report_hash) == 64  # SHA-256 hex = 64 chars

    def test_timeline_is_sorted_chronologically(self, json_generator, investigation_payload):
        """Timeline events must be sorted oldest→newest."""
        report = json_generator.generate(investigation_payload)
        timestamps = [e.timestamp for e in report.timeline]
        assert timestamps == sorted(timestamps)

    def test_all_10_sections_present(self, json_generator, investigation_payload):
        """All 10 required forensic sections must be present."""
        report = json_generator.generate(investigation_payload)
        assert report.case_summary is not None
        assert report.risk_score is not None
        assert report.sender_analysis is not None
        assert report.authentication is not None
        assert isinstance(report.malicious_ips, list)
        assert isinstance(report.malicious_urls, list)
        assert isinstance(report.reputation_scores, list)
        assert isinstance(report.timeline, list)
        assert report.correlation_graph is not None
        assert report.evidence is not None

    def test_generated_at_is_utc(self, json_generator, investigation_payload):
        """generated_at timestamp must be timezone-aware UTC."""
        report = json_generator.generate(investigation_payload)
        assert report.generated_at.tzinfo is not None

    def test_report_version_is_set(self, json_generator, investigation_payload):
        """Report version must be set."""
        report = json_generator.generate(investigation_payload)
        assert report.report_version == "1.0.0"

    def test_generated_by_is_set(self, json_generator, investigation_payload):
        """generated_by field must identify the Reports Engine."""
        report = json_generator.generate(investigation_payload)
        assert "TraceMail AI" in report.generated_by


class TestJSONSerialization:
    """Tests for JSONReportGenerator.to_json() and to_dict()"""

    def test_to_json_returns_valid_json_string(self, json_generator, investigation_payload):
        """to_json() output must be parseable JSON."""
        report = json_generator.generate(investigation_payload)
        raw = json_generator.to_json(report)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_to_json_contains_investigation_id(self, json_generator, investigation_payload):
        """Serialised JSON must include the investigation_id."""
        report = json_generator.generate(investigation_payload)
        raw = json_generator.to_json(report)
        assert investigation_payload.investigation_id in raw

    def test_to_json_exclude_evidence_body(self, json_generator, investigation_payload):
        """exclude_evidence_body=True must strip html/text bodies."""
        report = json_generator.generate(investigation_payload)
        raw = json_generator.to_json(report, exclude_evidence_body=True)
        parsed = json.loads(raw)
        assert "email_body_text" not in parsed["evidence"]
        assert "email_body_html" not in parsed["evidence"]

    def test_to_dict_returns_plain_dict(self, json_generator, investigation_payload):
        """to_dict() must return a plain Python dict (not Pydantic model)."""
        report = json_generator.generate(investigation_payload)
        d = json_generator.to_dict(report)
        assert isinstance(d, dict)
        assert "report_id" in d

    def test_to_json_custom_indent(self, json_generator, investigation_payload):
        """Custom indent parameter is respected."""
        report = json_generator.generate(investigation_payload)
        raw_2 = json_generator.to_json(report, indent=2)
        raw_4 = json_generator.to_json(report, indent=4)
        # 4-space indent produces larger output
        assert len(raw_4) > len(raw_2)


class TestSchemaValidation:
    """Tests that generated reports pass JSON Schema validation."""

    def test_generated_report_passes_schema(self, json_generator, investigation_payload):
        """Generated report must pass all JSON Schema Draft-07 checks."""
        report = json_generator.generate(investigation_payload)
        errors = validate_report_dict(json_generator.to_dict(report))
        assert errors == [], f"Schema validation errors: {errors}"

    def test_risk_score_bounds_validated(self):
        """RiskScore must reject values outside 0-100."""
        with pytest.raises(ValidationError):
            RiskScore(
                overall_score=150.0,  # invalid
                verdict=VerdictEnum.MALICIOUS,
                confidence=0.9,
            )

    def test_confidence_bounds_validated(self):
        """Confidence must be between 0.0 and 1.0."""
        with pytest.raises(ValidationError):
            RiskScore(
                overall_score=80.0,
                verdict=VerdictEnum.MALICIOUS,
                confidence=1.5,  # invalid
            )


class TestPayloadValidation:
    """Tests for JSONReportGenerator.validate_payload()"""

    def test_validates_dict_to_investigation_payload(self, json_generator, investigation_payload):
        """validate_payload() converts a dict to InvestigationPayload."""
        raw = json.loads(investigation_payload.model_dump_json())
        validated = json_generator.validate_payload(raw)
        assert isinstance(validated, InvestigationPayload)
        assert validated.investigation_id == investigation_payload.investigation_id

    def test_raises_on_missing_required_fields(self, json_generator):
        """validate_payload() raises ValidationError on missing required fields."""
        with pytest.raises(ValidationError):
            json_generator.validate_payload({"investigation_id": "INV-001"})

    def test_raises_on_id_mismatch(self, json_generator, investigation_payload):
        """InvestigationPayload raises if case_summary.investigation_id differs."""
        raw = json.loads(investigation_payload.model_dump_json())
        raw["case_summary"]["investigation_id"] = "DIFFERENT-ID"
        with pytest.raises(ValidationError):
            json_generator.validate_payload(raw)
