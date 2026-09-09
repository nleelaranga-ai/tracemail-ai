"""
TraceMail AI Backend — Forensic Report Generation Service
"""
import io
import json
from datetime import datetime, timezone
from typing import Dict, Any

from backend.models.scan import Investigation
from backend.utils.logger import logger

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False


class ReportService:
    @classmethod
    def generate_json_report(cls, inv: Investigation) -> Dict[str, Any]:
        """Generates machine-readable JSON forensic report for CERT-In / SOC ingestion."""
        return {
            "report_metadata": {
                "investigation_id": inv.id,
                "platform": "TraceMail AI",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "classification": "TLP:AMBER",
                "status": inv.status
            },
            "case_summary": {
                "sender": inv.sender,
                "recipient": inv.recipient,
                "subject": inv.subject,
                "received_at": inv.received_at.isoformat() if inv.received_at else None,
                "phishing_score": inv.phishing_score,
                "verdict": inv.verdict,
                "explanation": inv.explanation
            },
            "authentication_checks": inv.auth_results or {},
            "extracted_entities": inv.entities or {},
            "threat_indicators": inv.threat_results or [],
            "server_hop_timeline": inv.hop_timeline or [],
            "attack_graph": inv.attack_graph or {},
            "geojson_map": inv.geojson_map or {}
        }

    @classmethod
    def generate_pdf_report_bytes(cls, inv: Investigation) -> bytes:
        """Generates forensic PDF report as binary bytes."""
        if _HAS_REPORTLAB:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            elements = []

            # Header / Title
            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=22,
                leading=26,
                textColor=colors.HexColor("#0f172a")
            )
            elements.append(Paragraph("TraceMail AI — Forensic Investigation Report", title_style))
            elements.append(Paragraph("Smart India Hackathon 2026 • AI-Powered Cyber Threat Intelligence", styles["Normal"]))
            elements.append(Spacer(1, 15))

            # Case Overview Table
            verdict_color = colors.HexColor("#dc2626") if inv.verdict == "phishing" else colors.HexColor("#16a34a")
            data = [
                ["Investigation ID", inv.id, "Verdict", inv.verdict.upper()],
                ["Sender", inv.sender or "N/A", "Threat Score", f"{inv.phishing_score} / 100"],
                ["Subject", inv.subject or "N/A", "Date", inv.received_at.strftime('%Y-%m-%d %H:%M') if inv.received_at else "N/A"],
            ]
            t = Table(data, colWidths=[110, 200, 90, 140])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (3, 0), (3, 0), verdict_color),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 15))

            # Executive Summary
            elements.append(Paragraph("<b>Forensic Analysis & Findings:</b>", styles["Heading3"]))
            elements.append(Paragraph(inv.explanation or "No critical anomalies detected.", styles["Normal"]))
            elements.append(Spacer(1, 15))

            # Indicators Table
            elements.append(Paragraph("<b>Enriched Threat Indicators (IOCs):</b>", styles["Heading3"]))
            ioc_data = [["Type", "Indicator", "Reputation", "Status"]]
            for item in (inv.threat_results or []):
                ioc_data.append([
                    item.get("type", "").upper(),
                    str(item.get("value", ""))[:45],
                    str(item.get("reputation", "0")),
                    "MALICIOUS" if item.get("malicious") else "CLEAN"
                ])
            if len(ioc_data) == 1:
                ioc_data.append(["-", "No external indicators flagged", "-", "CLEAN"])

            ioc_table = Table(ioc_data, colWidths=[80, 260, 90, 110])
            ioc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            elements.append(ioc_table)

            doc.build(elements)
            return buffer.getvalue()

        # Clean fallback PDF payload if reportlab is not present
        content = (
            f"%PDF-1.4\n"
            f"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            f"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            f"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
            f"4 0 obj << /Length 200 >> stream\n"
            f"BT /F1 16 Tf 50 720 Td (TraceMail AI Forensic Report - Case: {inv.id}) Tj\n"
            f"/F1 12 Tf 0 -30 Td (Verdict: {inv.verdict.upper()} | Score: {inv.phishing_score}) Tj\n"
            f"0 -25 Td (Sender: {inv.sender or 'Unknown'}) Tj\n"
            f"0 -25 Td (Subject: {inv.subject or 'No Subject'}) Tj ET\n"
            f"endstream\nendobj\n"
            f"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
            f"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000244 00000 n \n0000000495 00000 n \n"
            f"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n574\n%%EOF"
        )
        return content.encode("latin1")
