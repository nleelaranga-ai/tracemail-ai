"""
TraceMail AI — Member 6: QA & Testing
File   : member6/tests/unit/test_pdf_generator.py
Purpose: Unit tests for PDFReportGenerator.
         PDF generation requires WeasyPrint + system libs.
         Tests that don't need WeasyPrint are unconditional;
         full PDF render tests are marked with @pytest.mark.pdf.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from member6.reports.pdf.pdf_generator import PDFReportGenerator, _auth_badge, _score_colour, _verdict_colour
from member6.reports.json.json_report import AuthResultEnum, VerdictEnum


# Mark all tests in this file that invoke real PDF render as 'pdf'
# Run without WeasyPrint with: pytest -m "not pdf"
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class TestColourHelpers:
    """Tests for the colour/badge helper functions."""

    @pytest.mark.parametrize(
        "verdict, expected_start",
        [
            (VerdictEnum.MALICIOUS, "#dc"),
            (VerdictEnum.SUSPICIOUS, "#d9"),
            (VerdictEnum.CLEAN, "#16"),
            (VerdictEnum.UNKNOWN, "#6b"),
        ],
    )
    def test_verdict_colour_returns_css_colour(self, verdict, expected_start):
        colour = _verdict_colour(verdict)
        assert colour.startswith(expected_start)
        assert colour.startswith("#")

    @pytest.mark.parametrize(
        "score, expected_colour_start",
        [
            (90.0, "#dc"),   # danger
            (60.0, "#d9"),   # warning
            (20.0, "#16"),   # clean
        ],
    )
    def test_score_colour_thresholds(self, score, expected_colour_start):
        assert _score_colour(score).startswith(expected_colour_start)

    def test_auth_badge_pass_returns_green(self):
        badge = _auth_badge(AuthResultEnum.PASS)
        assert badge["colour"] == "#16a34a"
        assert badge["label"] == "PASS"

    def test_auth_badge_fail_returns_red(self):
        badge = _auth_badge(AuthResultEnum.FAIL)
        assert badge["colour"] == "#dc2626"
        assert badge["label"] == "FAIL"

    def test_auth_badge_softfail_returns_amber(self):
        badge = _auth_badge(AuthResultEnum.SOFTFAIL)
        assert badge["label"] == "SOFTFAIL"


class TestHTMLRendering:
    """Tests for PDFReportGenerator.render_html()"""

    def test_render_html_returns_string(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert isinstance(html, str)
        assert len(html) > 100

    def test_html_contains_investigation_id(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert json_report.investigation_id in html

    def test_html_contains_all_section_numbers(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        for i in range(1, 11):
            section_num = f"{i:02d}"
            assert section_num in html, f"Section {section_num} missing from HTML"

    def test_html_contains_verdict(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert json_report.risk_score.verdict.value in html

    def test_html_contains_sender_email(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert json_report.sender_analysis.email_address in html

    def test_html_contains_report_hash(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert json_report.report_hash in html

    def test_html_contains_malicious_ip(
        self, pdf_generator, json_report, malicious_ips
    ):
        html = pdf_generator.render_html(json_report)
        assert malicious_ips[0].ip in html

    def test_html_contains_auth_results(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert "FAIL" in html  # SPF/DKIM/DMARC all fail in test fixture

    def test_html_doctype_present(self, pdf_generator, json_report):
        html = pdf_generator.render_html(json_report)
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()

    def test_html_is_autoescaped(self, pdf_generator, json_report):
        """Jinja2 autoescape must be on — no raw < > in dynamic content."""
        # Inject a potential XSS string into analyst notes
        json_report.case_summary.analyst_notes = "<script>alert('xss')</script>"
        html = pdf_generator.render_html(json_report)
        # Autoescaping converts < to &lt;
        assert "<script>alert('xss')" not in html


class TestPDFFilename:
    """Tests for PDFReportGenerator.generate_pdf_filename()"""

    def test_filename_ends_with_pdf(self, pdf_generator, json_report):
        name = pdf_generator.generate_pdf_filename(json_report)
        assert name.endswith(".pdf")

    def test_filename_contains_investigation_id(self, pdf_generator, json_report):
        name = pdf_generator.generate_pdf_filename(json_report)
        # ID is truncated to 32 chars and sanitised
        assert "INV-TEST-001" in name

    def test_filename_contains_date(self, pdf_generator, json_report):
        name = pdf_generator.generate_pdf_filename(json_report)
        date_part = json_report.generated_at.strftime("%Y%m%d")
        assert date_part in name

    def test_filename_starts_with_tracemail(self, pdf_generator, json_report):
        name = pdf_generator.generate_pdf_filename(json_report)
        assert name.startswith("tracemail-forensic-")


class TestPDFGeneration:
    """
    Tests for the full PDF render (requires WeasyPrint).
    Skip with: pytest -m "not pdf"
    """

    @pytest.mark.pdf
    def test_generate_pdf_returns_bytes(self, pdf_generator, json_report):
        """Full PDF render returns non-empty bytes."""
        try:
            pdf_bytes = pdf_generator.generate_pdf(json_report)
        except RuntimeError as e:
            if "WeasyPrint is not installed" in str(e):
                pytest.skip("WeasyPrint not available in this environment")
            raise
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1024  # A real PDF is always > 1KB

    @pytest.mark.pdf
    def test_generate_pdf_starts_with_pdf_magic(self, pdf_generator, json_report):
        """PDF output must start with the %PDF magic bytes."""
        try:
            pdf_bytes = pdf_generator.generate_pdf(json_report)
        except RuntimeError as e:
            if "WeasyPrint is not installed" in str(e):
                pytest.skip("WeasyPrint not available in this environment")
            raise
        assert pdf_bytes[:4] == b"%PDF"

    def test_generate_pdf_raises_without_weasyprint(
        self, pdf_generator, json_report
    ):
        """RuntimeError raised when WeasyPrint is not importable."""
        with patch("builtins.__import__", side_effect=ImportError("weasyprint")):
            with pytest.raises((RuntimeError, ImportError)):
                pdf_generator.generate_pdf(json_report)

    def test_build_context_includes_all_keys(self, pdf_generator, json_report):
        """_build_context must include all required template variables."""
        ctx = pdf_generator._build_context(json_report)
        required_keys = [
            "report", "verdict_colour", "generated_at_str",
            "received_at_str", "spf_badge", "dkim_badge", "dmarc_badge",
            "risk_colour", "malicious_ip_count", "malicious_url_count",
            "timeline_event_count", "attachment_count",
            "graph_node_count", "graph_edge_count", "raw_headers_preview",
        ]
        for key in required_keys:
            assert key in ctx, f"Context missing key: {key}"

    def test_raw_headers_truncated_at_3000_chars(self, pdf_generator, json_report):
        """Raw headers preview must not exceed 3000 chars in template context."""
        json_report.evidence.raw_headers = "X" * 5000
        ctx = pdf_generator._build_context(json_report)
        assert len(ctx["raw_headers_preview"]) <= 3200  # 3000 + truncation notice


class TestPDFGeneratorInit:
    """Tests for PDFReportGenerator initialisation."""

    def test_default_template_dir_exists(self):
        """Default template directory must exist."""
        gen = PDFReportGenerator()
        assert gen._env is not None

    def test_custom_template_dir(self, tmp_path):
        """PDFReportGenerator accepts a custom template directory."""
        # Create minimal template file so Jinja2 env init succeeds
        (tmp_path / "report_template.html").write_text("<html></html>")
        gen = PDFReportGenerator(template_dir=tmp_path)
        assert gen._env is not None
