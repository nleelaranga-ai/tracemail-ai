"""
TraceMail AI — Member 6: Reports Engine
File   : member6/reports/pdf/pdf_generator.py
Purpose: Converts a JSONReport into a production-grade forensic PDF report
         using WeasyPrint (HTML+CSS → PDF) and Jinja2 templating.

Integration:
    GET /api/report/pdf/{investigationId}
      → Backend assembles InvestigationPayload
      → json_report.JSONReportGenerator.generate(payload) → JSONReport
      → pdf_generator.PDFReportGenerator.generate_pdf(report) → bytes
      → FastAPI StreamingResponse(bytes, media_type="application/pdf")

Dependencies:
    pip install weasyprint jinja2 python-dateutil

WeasyPrint requires system libs (libpango, libcairo) — see Dockerfile.
"""

from __future__ import annotations

import io
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from member6.reports.json.json_report import (
    AuthResultEnum,
    JSONReport,
    VerdictEnum,
)

logger = logging.getLogger(__name__)

# Template directory is sibling to this file at ../templates/
_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


# ---------------------------------------------------------------------------
# Template context helpers
# ---------------------------------------------------------------------------


def _verdict_colour(verdict: VerdictEnum) -> str:
    """Return a CSS colour token for the risk verdict badge."""
    return {
        VerdictEnum.MALICIOUS: "#dc2626",    # red-600
        VerdictEnum.SUSPICIOUS: "#d97706",   # amber-600
        VerdictEnum.CLEAN: "#16a34a",        # green-600
        VerdictEnum.UNKNOWN: "#6b7280",      # gray-500
    }.get(verdict, "#6b7280")


def _auth_badge(result: AuthResultEnum) -> dict[str, str]:
    """Return label + colour for an SPF/DKIM/DMARC badge."""
    colour_map = {
        AuthResultEnum.PASS: ("#16a34a", "PASS"),
        AuthResultEnum.FAIL: ("#dc2626", "FAIL"),
        AuthResultEnum.SOFTFAIL: ("#d97706", "SOFTFAIL"),
        AuthResultEnum.NEUTRAL: ("#6b7280", "NEUTRAL"),
        AuthResultEnum.NONE: ("#6b7280", "NONE"),
        AuthResultEnum.TEMPERROR: ("#7c3aed", "TEMPERROR"),
        AuthResultEnum.PERMERROR: ("#7c3aed", "PERMERROR"),
    }
    colour, label = colour_map.get(result, ("#6b7280", result.value.upper()))
    return {"colour": colour, "label": label}


def _score_colour(score: float) -> str:
    """Return a CSS colour for a 0-100 numeric threat score."""
    if score >= 75:
        return "#dc2626"
    if score >= 45:
        return "#d97706"
    return "#16a34a"


def _format_dt(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Format a datetime to a human-readable string."""
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(fmt)


def _truncate(text: str | None, max_len: int = 80) -> str:
    """Truncate long strings for display in constrained table cells."""
    if text is None:
        return "N/A"
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


def _safe_url_fetcher(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """
    Security-hardened URL fetcher for WeasyPrint.
    Prevents SSRF, Local File Inclusion (LFI), and Cloud Metadata access.
    Blocks:
      - file:// (outside template directory)
      - localhost, 127.0.0.1, 0.0.0.0, ::1
      - 169.254.169.254 (cloud metadata)
      - internal/private network IP ranges (RFC 1918)
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme == "file":
        template_uri = _TEMPLATE_DIR.as_uri()
        if not url.startswith(template_uri):
            logger.warning("Blocked unsafe file:// access attempt: %s", url)
            raise ValueError(f"Blocked unsafe local file access: {url}")
        from weasyprint import default_url_fetcher  # type: ignore[import-untyped, import-not-found]
        return default_url_fetcher(url, *args, **kwargs)

    if scheme in ("http", "https"):
        hostname = (parsed.hostname or "").lower()

        # Block loopback, link-local, and cloud metadata hostnames
        blocked_hosts = {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",
            "metadata.google.internal",
            "instance-data",
        }
        if hostname in blocked_hosts or hostname.endswith(".localhost"):
            logger.warning("Blocked SSRF attempt to internal host: %s", hostname)
            raise ValueError(f"Blocked access to internal host: {hostname}")

        # Check for private, link-local, loopback, or reserved IP addresses
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                logger.warning("Blocked private network fetch attempt: %s (%s)", url, ip)
                raise ValueError(f"Blocked private network address: {ip}")
        except ValueError:
            # Domain name, not a direct IP literal
            pass

        from weasyprint import default_url_fetcher  # type: ignore[import-untyped, import-not-found]
        return default_url_fetcher(url, *args, **kwargs)

    logger.warning("Blocked unsupported/unsafe URL scheme: %s", scheme)
    raise ValueError(f"Blocked unsafe protocol scheme: {scheme}")


# ---------------------------------------------------------------------------
# PDF Report Generator
# ---------------------------------------------------------------------------


class PDFReportGenerator:
    """
    Generates forensic PDF reports from a JSONReport instance.

    The generator is stateless and thread-safe. Each call to generate_pdf()
    creates an independent in-memory PDF document.

    Usage:
        gen    = PDFReportGenerator()
        pdf_bytes = gen.generate_pdf(report)
        # → StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf")
    """

    def __init__(self, template_dir: Path = _TEMPLATE_DIR) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Register custom filters
        self._env.filters["verdict_colour"] = _verdict_colour
        self._env.filters["auth_badge"] = _auth_badge
        self._env.filters["score_colour"] = _score_colour
        self._env.filters["format_dt"] = _format_dt
        self._env.filters["truncate_str"] = _truncate

    def _build_context(self, report: JSONReport) -> dict[str, Any]:
        """
        Build the full Jinja2 template context from the report.
        Adds derived / display-ready values on top of the raw report data.
        """
        auth = report.authentication
        return {
            # Raw report (all sections available in template)
            "report": report,
            # Derived display values
            "verdict_colour": _verdict_colour(report.risk_score.verdict),
            "generated_at_str": _format_dt(report.generated_at),
            "received_at_str": _format_dt(report.case_summary.received_at),
            "spf_badge": _auth_badge(auth.spf_result),
            "dkim_badge": _auth_badge(auth.dkim_result),
            "dmarc_badge": _auth_badge(auth.dmarc_result),
            "risk_colour": _score_colour(report.risk_score.overall_score),
            # Summary counts for the cover page
            "malicious_ip_count": len(report.malicious_ips),
            "malicious_url_count": len(report.malicious_urls),
            "timeline_event_count": len(report.timeline),
            "attachment_count": len(report.evidence.attachments),
            # Truncated raw headers for PDF (full version in JSON report)
            "raw_headers_preview": (
                report.evidence.raw_headers[:3000]
                + ("\n... [truncated — see JSON report for full headers]"
                   if len(report.evidence.raw_headers) > 3000 else "")
            ),
            # Correlation stats
            "graph_node_count": len(report.correlation_graph.nodes),
            "graph_edge_count": len(report.correlation_graph.edges),
        }

    def render_html(self, report: JSONReport) -> str:
        """
        Render the Jinja2 HTML template to a string.
        Useful for debugging template output before converting to PDF.

        Args:
            report: Validated JSONReport instance.

        Returns:
            str: Rendered HTML string.
        """
        template = self._env.get_template("report_template.html")
        context = self._build_context(report)
        return template.render(**context)

    def generate_pdf(self, report: JSONReport) -> bytes:
        """
        Render the HTML template and convert to PDF bytes via WeasyPrint.

        Args:
            report: Validated JSONReport instance.

        Returns:
            bytes: Binary PDF data ready for streaming to client.

        Raises:
            RuntimeError: If WeasyPrint fails to produce a valid PDF.
        """
        try:
            # Import here so WeasyPrint's GTK/pango init doesn't run at
            # module load time (important for testing environments).
            from weasyprint import CSS, HTML  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "WeasyPrint is not installed. "
                "Run: pip install weasyprint"
            ) from exc

        html_content = self.render_html(report)

        # Resolve the base URL so WeasyPrint can resolve relative assets
        # (CSS, fonts) referenced in the HTML template.
        base_url = _TEMPLATE_DIR.as_uri()

        logger.info(
            "Generating PDF for investigation_id=%s report_id=%s",
            report.investigation_id,
            report.report_id,
        )

        try:
            pdf_bytes_io = io.BytesIO()
            html_doc = HTML(
                string=html_content,
                base_url=base_url,
                url_fetcher=_safe_url_fetcher,
            )
            html_doc.write_pdf(pdf_bytes_io)
            pdf_bytes = pdf_bytes_io.getvalue()
        except Exception as exc:
            logger.exception("WeasyPrint failed for report_id=%s", report.report_id)
            raise RuntimeError(
                f"PDF generation failed for report {report.report_id}: {exc}"
            ) from exc

        if not pdf_bytes:
            raise RuntimeError(
                f"WeasyPrint produced an empty PDF for report {report.report_id}"
            )

        logger.info(
            "PDF generated successfully: report_id=%s size=%d bytes",
            report.report_id,
            len(pdf_bytes),
        )
        return pdf_bytes

    def generate_pdf_filename(self, report: JSONReport) -> str:
        """
        Produce a safe, descriptive filename for the PDF download.

        Returns:
            str: e.g. "tracemail-forensic-INV-abc123-20260908.pdf"
        """
        date_str = report.generated_at.strftime("%Y%m%d")
        safe_id = report.investigation_id.replace("/", "-").replace(" ", "_")[:32]
        return f"tracemail-forensic-{safe_id}-{date_str}.pdf"
