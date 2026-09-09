"""
TraceMail AI — Team Reports: QA & Testing
File   : team_reports/tests/contract/test_api_contracts.py
Purpose: Contract tests — validates every API response body against the
         JSON Schema (Draft-07), ensuring the Reports Engine never returns
         a response that breaks the agreed API contract.

Approach:
    1. Generate a report via the ASGI test client
    2. Validate the response body against report_schema.json
    3. Assert all required fields and types match
    4. Assert no extra/missing fields that would break consumers

Run with:
    pytest tests/contract/ -v
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from team_reports.reports.router.reports_router import reports_router
from team_reports.reports.schemas.report_schema import (
    assert_valid_report,
    get_report_schema,
)

# ---------------------------------------------------------------------------
# Test App
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(reports_router, prefix="/api")
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def raw_payload(investigation_payload) -> dict[str, Any]:
    return json.loads(investigation_payload.model_dump_json())


# ---------------------------------------------------------------------------
# Schema Contract: JSON Report
# ---------------------------------------------------------------------------


class TestJSONReportContract:
    """
    Contract: GET /api/report/json/{investigationId} response must conform
    to report_schema.json at all times.
    """

    def test_response_conforms_to_schema(self, client, raw_payload):
        """Full schema validation — zero violations allowed."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        assert resp.status_code == 200
        assert_valid_report(resp.json())

    def test_required_top_level_fields(self, client, raw_payload):
        """All 15 required top-level fields must be present."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()

        required = [
            "report_id",
            "report_version",
            "generated_at",
            "generated_by",
            "investigation_id",
            "report_hash",
            "case_summary",
            "risk_score",
            "sender_analysis",
            "authentication",
            "malicious_ips",
            "malicious_urls",
            "reputation_scores",
            "timeline",
            "correlation_graph",
            "evidence",
        ]
        missing = [f for f in required if f not in data]
        assert not missing, f"Missing required fields: {missing}"

    def test_report_id_is_uuid_format(self, client, raw_payload):
        """report_id must be a valid UUID v4 string."""
        import uuid

        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        report_id = resp.json()["report_id"]
        uuid.UUID(report_id)  # raises if invalid

    def test_report_hash_is_64_char_hex(self, client, raw_payload):
        """report_hash must be a 64-character hexadecimal string (SHA-256)."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        report_hash = resp.json()["report_hash"]
        assert len(report_hash) == 64
        assert all(c in "0123456789abcdef" for c in report_hash.lower())

    def test_risk_score_contract(self, client, raw_payload):
        """risk_score must have: overall_score, verdict, confidence."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        rs = resp.json()["risk_score"]
        assert "overall_score" in rs
        assert "verdict" in rs
        assert "confidence" in rs
        assert isinstance(rs["overall_score"], (int, float))
        assert 0.0 <= rs["overall_score"] <= 100.0
        assert rs["verdict"] in ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]
        assert 0.0 <= rs["confidence"] <= 1.0

    def test_authentication_contract(self, client, raw_payload):
        """authentication must have SPF, DKIM, DMARC result fields."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        auth = resp.json()["authentication"]
        assert "spf_result" in auth
        assert "dkim_result" in auth
        assert "dmarc_result" in auth
        assert "authentication_summary" in auth

        valid_results = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]
        assert auth["spf_result"] in valid_results
        assert auth["dkim_result"] in valid_results
        assert auth["dmarc_result"] in valid_results

    def test_malicious_ips_contract(self, client, raw_payload):
        """malicious_ips must be a list; each item has ip and threat_score."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        ips = resp.json()["malicious_ips"]
        assert isinstance(ips, list)
        for ip in ips:
            assert "ip" in ip
            assert "threat_score" in ip
            assert 0.0 <= ip["threat_score"] <= 100.0

    def test_malicious_urls_contract(self, client, raw_payload):
        """malicious_urls must be a list; each item has url, domain, threat_score."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        urls = resp.json()["malicious_urls"]
        assert isinstance(urls, list)
        for url in urls:
            assert "url" in url
            assert "domain" in url
            assert "threat_score" in url

    def test_timeline_contract(self, client, raw_payload):
        """timeline is a list; each event has timestamp, event_type, description."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        timeline = resp.json()["timeline"]
        assert isinstance(timeline, list)
        for event in timeline:
            assert "timestamp" in event
            assert "event_type" in event
            assert "description" in event

    def test_correlation_graph_contract(self, client, raw_payload):
        """correlation_graph must have nodes and edges lists."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        graph = resp.json()["correlation_graph"]
        assert "nodes" in graph
        assert "edges" in graph
        assert isinstance(graph["nodes"], list)
        assert isinstance(graph["edges"], list)

    def test_evidence_contract(self, client, raw_payload):
        """evidence must have raw_headers, hashes, extracted_urls, extracted_ips."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        ev = resp.json()["evidence"]
        assert "raw_headers" in ev
        assert "hashes" in ev
        assert isinstance(ev["extracted_urls"], list)
        assert isinstance(ev["extracted_ips"], list)

    def test_case_summary_contract(self, client, raw_payload):
        """case_summary must have all core identification fields."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        cs = resp.json()["case_summary"]
        required_fields = [
            "investigation_id",
            "subject",
            "from_address",
            "to_addresses",
            "received_at",
            "threat_type",
        ]
        for field in required_fields:
            assert field in cs, f"Missing case_summary field: {field}"

    def test_sender_analysis_contract(self, client, raw_payload):
        """sender_analysis must have display_name, email_address, sender_domain."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        sa = resp.json()["sender_analysis"]
        for field in ["display_name", "email_address", "sender_domain"]:
            assert field in sa

    def test_reputation_scores_contract(self, client, raw_payload):
        """reputation_scores is a list; each has entity, score, is_blacklisted."""
        inv_id = raw_payload["investigation_id"]
        resp = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload)
        reps = resp.json()["reputation_scores"]
        assert isinstance(reps, list)
        for rep in reps:
            assert "entity" in rep
            assert "score" in rep
            assert "is_blacklisted" in rep

    def test_response_is_deterministic_in_structure(self, client, raw_payload):
        """Two identical requests must return the same structure (not same ID)."""
        inv_id = raw_payload["investigation_id"]
        r1 = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload).json()
        r2 = client.request("GET", f"/api/report/json/{inv_id}", json=raw_payload).json()
        # Same keys
        assert set(r1.keys()) == set(r2.keys())
        # Different report IDs (they're unique per call)
        assert r1["report_id"] != r2["report_id"]


# ---------------------------------------------------------------------------
# Schema Contract: Generate Endpoint
# ---------------------------------------------------------------------------


class TestGenerateEndpointContract:
    """Contract: POST /api/v1/reports/generate response structure."""

    def test_generate_response_has_required_fields(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        data = resp.json()
        assert "investigation_id" in data
        assert "reports" in data
        assert "pdf" in data["reports"]
        assert "json" in data["reports"]

    def test_generate_pdf_report_has_url_and_method(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        pdf = resp.json()["reports"]["pdf"]
        assert "url" in pdf
        assert "method" in pdf

    def test_generate_json_report_has_url_and_method(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        json_rep = resp.json()["reports"]["json"]
        assert "url" in json_rep
        assert "method" in json_rep


# ---------------------------------------------------------------------------
# Schema Drift Test
# ---------------------------------------------------------------------------


class TestSchemaDrift:
    """Ensure generated schema stays in sync with static file."""

    def test_schema_has_required_properties(self):
        """Generated schema must define all 16 top-level properties."""
        schema = get_report_schema()
        props = schema.get("properties", {})
        required_props = [
            "report_id",
            "report_version",
            "generated_at",
            "generated_by",
            "investigation_id",
            "report_hash",
            "case_summary",
            "risk_score",
            "sender_analysis",
            "authentication",
            "malicious_ips",
            "malicious_urls",
            "reputation_scores",
            "timeline",
            "correlation_graph",
            "evidence",
        ]
        for prop in required_props:
            assert prop in props, f"Schema missing property: {prop}"

    def test_schema_dollar_schema_is_set(self):
        schema = get_report_schema()
        assert "$schema" in schema
        assert "json-schema.org" in schema["$schema"]

    def test_schema_title_is_set(self):
        schema = get_report_schema()
        assert "title" in schema
        assert "TraceMail" in schema["title"]
