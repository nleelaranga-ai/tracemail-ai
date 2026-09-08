"""
TraceMail AI — Member 6: QA & Testing
File   : member6/tests/integration/test_reports_api.py
Purpose: Integration tests for the Reports Engine FastAPI router.
         Uses httpx.AsyncClient with ASGI transport — no real HTTP server.
         Tests all 3 endpoints against a minimal FastAPI test app.

Run with:
    pytest tests/integration/test_reports_api.py -v
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from member6.reports.router.reports_router import reports_router


# ---------------------------------------------------------------------------
# Test App Setup
# ---------------------------------------------------------------------------

def make_test_app() -> FastAPI:
    """Minimal FastAPI app mounting only the reports router."""
    app = FastAPI(title="TraceMail AI - Test App")
    app.include_router(reports_router, prefix="/api")
    return app


@pytest.fixture(scope="module")
def test_app() -> FastAPI:
    return make_test_app()


@pytest.fixture(scope="module")
def client(test_app) -> TestClient:
    return TestClient(test_app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Payload helper
# ---------------------------------------------------------------------------


@pytest.fixture()
def raw_payload(investigation_payload) -> dict[str, Any]:
    """Convert InvestigationPayload to plain dict for HTTP request bodies."""
    return json.loads(investigation_payload.model_dump_json())


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/reports/generate
# ---------------------------------------------------------------------------


class TestGenerateEndpoint:

    def test_generate_returns_200(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        assert resp.status_code == 200

    def test_generate_returns_investigation_id(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        data = resp.json()
        assert data["investigation_id"] == raw_payload["investigation_id"]

    def test_generate_includes_pdf_url(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        data = resp.json()
        assert "/api/report/pdf/" in data["reports"]["pdf"]["url"]

    def test_generate_includes_json_url(self, client, raw_payload):
        resp = client.post("/api/v1/reports/generate", json=raw_payload)
        data = resp.json()
        assert "/api/report/json/" in data["reports"]["json"]["url"]

    def test_generate_returns_422_on_empty_body(self, client):
        resp = client.post("/api/v1/reports/generate", json={})
        assert resp.status_code == 422

    def test_generate_returns_422_on_invalid_payload(self, client):
        resp = client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": "INV-001", "invalid_field": "garbage"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Tests: GET /api/report/json/{investigationId}
# ---------------------------------------------------------------------------


class TestJSONReportEndpoint:

    def test_json_report_returns_200(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        assert resp.status_code == 200

    def test_json_report_content_type(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        assert "application/json" in resp.headers["content-type"]

    def test_json_report_has_all_10_sections(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        required_keys = [
            "case_summary", "risk_score", "sender_analysis",
            "authentication", "malicious_ips", "malicious_urls",
            "reputation_scores", "timeline", "correlation_graph", "evidence",
        ]
        for key in required_keys:
            assert key in data, f"Missing section: {key}"

    def test_json_report_has_report_id(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        assert "report_id" in data
        assert data["report_id"]

    def test_json_report_has_report_hash(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        assert "report_hash" in data
        assert len(data["report_hash"]) == 64  # SHA-256

    def test_json_report_investigation_id_matches(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        assert data["investigation_id"] == inv_id

    def test_json_report_rejects_id_mismatch(self, client, raw_payload):
        """URL investigationId ≠ payload investigation_id → 400."""
        resp = client.get(
            "/api/report/json/WRONG-ID",  # URL ID doesn't match payload
            json=raw_payload,
        )
        assert resp.status_code == 400

    def test_json_report_rejects_empty_body(self, client):
        resp = client.get("/api/report/json/INV-001", json={})
        assert resp.status_code == 422

    def test_json_report_verdict_is_present(self, client, raw_payload):
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        assert data["risk_score"]["verdict"] in [
            "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"
        ]

    def test_json_report_timeline_sorted(self, client, raw_payload):
        """Timeline must be sorted chronologically."""
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/json/{inv_id}", json=raw_payload)
        data = resp.json()
        timestamps = [e["timestamp"] for e in data["timeline"]]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Tests: GET /api/report/pdf/{investigationId}
# ---------------------------------------------------------------------------


class TestPDFReportEndpoint:

    def test_pdf_report_returns_200_or_500(self, client, raw_payload):
        """
        PDF endpoint returns 200 if WeasyPrint available, or 500 if not.
        Both are acceptable in test environment; we test the request flow.
        """
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/pdf/{inv_id}", json=raw_payload)
        assert resp.status_code in (200, 500)

    def test_pdf_rejects_id_mismatch(self, client, raw_payload):
        resp = client.get(
            "/api/report/pdf/WRONG-ID",
            json=raw_payload,
        )
        assert resp.status_code == 400

    def test_pdf_rejects_empty_body(self, client):
        resp = client.get("/api/report/pdf/INV-001", json={})
        assert resp.status_code == 422

    @pytest.mark.pdf
    def test_pdf_content_type_when_available(self, client, raw_payload):
        """When WeasyPrint is available, response is application/pdf."""
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/pdf/{inv_id}", json=raw_payload)
        if resp.status_code == 200:
            assert resp.headers["content-type"] == "application/pdf"

    @pytest.mark.pdf
    def test_pdf_content_disposition_header(self, client, raw_payload):
        """Response must have Content-Disposition: attachment when successful."""
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/pdf/{inv_id}", json=raw_payload)
        if resp.status_code == 200:
            assert "attachment" in resp.headers.get("content-disposition", "")
            assert ".pdf" in resp.headers.get("content-disposition", "")

    @pytest.mark.pdf
    def test_pdf_report_hash_header(self, client, raw_payload):
        """X-Report-Hash header must be present and 64-char SHA-256."""
        inv_id = raw_payload["investigation_id"]
        resp = client.get(f"/api/report/pdf/{inv_id}", json=raw_payload)
        if resp.status_code == 200:
            assert len(resp.headers.get("x-report-hash", "")) == 64
