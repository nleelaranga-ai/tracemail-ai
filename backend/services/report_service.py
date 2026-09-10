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
            "geojson_map": inv.geojson_map or {},
            "threat_score": inv.threat_score if inv.threat_score is not None else inv.phishing_score,
            "risk_level": inv.risk_level or "Unknown",
            "origin_ip": inv.origin_ip,
            "origin_city": inv.origin_city,
            "origin_country": inv.origin_country,
            "threat_intel": inv.threat_intel or {},
            "ai_analysis": inv.ai_analysis or {},
            "timeline": inv.timeline or [],
            "iocs": inv.iocs or []
        }

    @classmethod
    def generate_html_report(cls, inv: Investigation) -> str:
        """Generates a standalone forensic HTML report with dark cyber styling."""
        score = inv.threat_score if inv.threat_score is not None else inv.phishing_score
        risk = (inv.risk_level or "UNKNOWN").upper()
        risk_color = "#ef4444" if risk == "CRITICAL" else "#f97316" if risk == "HIGH" else "#eab308" if risk == "MEDIUM" else "#10b981"

        vt = (inv.threat_intel or {}).get("virustotal", {})
        abuse = (inv.threat_intel or {}).get("abuseipdb", {})
        whois_data = (inv.threat_intel or {}).get("whois", {})
        dns_data = (inv.threat_intel or {}).get("dns", {})
        geoip_data = (inv.threat_intel or {}).get("geoip", {})
        ai_data = inv.ai_analysis or {}
        reasons_html = "".join([f"<li>{r}</li>" for r in ai_data.get("reasons", [])]) or "<li>No critical flags detected.</li>"

        ioc_rows = ""
        for ioc in (inv.iocs or []):
            m_badge = '<span style="color:#ef4444;font-weight:bold;">MALICIOUS</span>' if ioc.get("malicious") else '<span style="color:#10b981;">BENIGN</span>'
            ioc_rows += f"<tr><td style='padding:8px;border:1px solid #334155;'>{ioc.get('type','').upper()}</td><td style='padding:8px;border:1px solid #334155;font-family:monospace;'>{ioc.get('value','')}</td><td style='padding:8px;border:1px solid #334155;'>{m_badge}</td></tr>"

        if not ioc_rows:
            ioc_rows = "<tr><td colspan='3' style='padding:8px;border:1px solid #334155;text-align:center;'>No IOCs recorded</td></tr>"

        timeline_steps = ""
        for step in (inv.timeline or []):
            st = step.get("status", "completed")
            timeline_steps += f"""
            <div style="margin-bottom:12px;padding-left:14px;border-left:3px solid #3b82f6;">
                <div style="font-weight:600;font-size:14px;color:#f8fafc;">Step {step.get('step', 1)}: {step.get('name', '')}</div>
                <div style="font-size:12px;color:#94a3b8;">{step.get('detail', '')} &bull; <span style="color:#38bdf8;">{st}</span></div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TraceMail AI — Forensic Report [{inv.id}]</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #e2e8f0; margin: 0; padding: 24px; }}
        .container {{ max-width: 960px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }}
        .title {{ font-size: 24px; font-weight: 700; color: #f8fafc; letter-spacing: -0.5px; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
        .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 13px; letter-spacing: 0.5px; }}
        .card {{ background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 20px; }}
        .card h3 {{ margin-top: 0; font-size: 16px; color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background-color: #0f172a; color: #94a3b8; text-align: left; padding: 10px 8px; border: 1px solid #334155; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        .metric {{ font-size: 28px; font-weight: 800; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="title">🛡️ TraceMail AI — Email Threat Forensic Report</div>
                <div class="subtitle">Smart India Hackathon 2026 &bull; Case ID: <code>{inv.id}</code> &bull; Classification: TLP:AMBER</div>
            </div>
            <div>
                <span class="badge" style="background-color: {risk_color}22; color: {risk_color}; border: 1px solid {risk_color};">{risk} RISK ({score}/100)</span>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h3>Case Summary</h3>
                <p><strong>Sender:</strong> {inv.sender or 'Unknown'}</p>
                <p><strong>Recipient:</strong> {inv.recipient or 'Unknown'}</p>
                <p><strong>Subject:</strong> {inv.subject or 'No Subject'}</p>
                <p><strong>Origin City:</strong> {inv.origin_city or 'Unknown'}, {inv.origin_country or 'Unknown'} ({inv.origin_ip or 'N/A'})</p>
                <p><strong>Verdict:</strong> <span style="color: {risk_color}; font-weight: 700;">{inv.verdict.upper()}</span></p>
            </div>
            <div class="card">
                <h3>Threat Intelligence Summary</h3>
                <p><strong>VirusTotal:</strong> {vt.get('positives', 0)}/{vt.get('total_engines', 88)} malicious flags</p>
                <p><strong>AbuseIPDB Score:</strong> {abuse.get('abuse_confidence_score', 0)}% confidence</p>
                <p><strong>Domain Age:</strong> {whois_data.get('domain_age_days', 'N/A')} days (Registrar: {whois_data.get('registrar', 'N/A')})</p>
                <p><strong>DNS Auth:</strong> SPF={dns_data.get('spf','none')}, DKIM={dns_data.get('dkim','none')}, DMARC={dns_data.get('dmarc','none')}</p>
                <p><strong>Origin ISP:</strong> {geoip_data.get('isp', 'N/A')} (ASN: {geoip_data.get('asn', 'N/A')})</p>
            </div>
        </div>

        <div class="card">
            <h3>AI Threat Analysis & Findings</h3>
            <p><strong>Model Prediction:</strong> {ai_data.get('prediction', inv.verdict)} (Confidence: {int(ai_data.get('confidence', 0.95) * 100)}%)</p>
            <p><strong>Executive Summary:</strong> {ai_data.get('summary', inv.explanation)}</p>
            <ul>{reasons_html}</ul>
        </div>

        <div class="card">
            <h3>Indicators of Compromise (IOCs)</h3>
            <table>
                <thead>
                    <tr><th>Type</th><th>Indicator</th><th>Verdict</th></tr>
                </thead>
                <tbody>
                    {ioc_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3>Investigation Execution Timeline</h3>
            {timeline_steps}
        </div>

        <div style="text-align: center; margin-top: 24px; font-size: 12px; color: #64748b;">
            Generated by TraceMail AI Defense Intelligence Platform &bull; Automated Forensic Report &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
    </div>
</body>
</html>
"""
        return html

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
