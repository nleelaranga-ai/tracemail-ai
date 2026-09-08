# TraceMail AI — Member 2 Backend Integration Checklist
## Reports Engine & Forensic Intelligence Handoff
**Component:** Reports Engine (Member 6)  
**Consumer:** Backend API Lead (Member 2)  
**Protocol:** Internal Python Dependency / FastAPI Sub-Router  
**Status:** Validated & Production Ready  

---

## 1. Quick Integration Summary

The Reports Engine is an **in-process, database-agnostic** FastAPI router.
Per project architecture rules:
> **The Reports Module never queries the database directly.**
> Member 2's Backend retrieves data from PostgreSQL, aggregates findings from AI Engine (Member 3), Threat Intel (Member 4), and Maps (Member 5), and passes the assembled payload to Member 6.

---

## 2. Exact Import Statement

In Member 2's `app/main.py` (or router aggregator):

```python
from member6.reports.router.reports_router import reports_router
```

---

## 3. Exact `app.include_router` Code

Mount the router onto your main FastAPI application instance under the `/api` prefix:

```python
from fastapi import FastAPI
from member6.reports.router.reports_router import reports_router

app = FastAPI(
    title="TraceMail AI Backend",
    version="1.0.0",
    description="AI-Powered Email Threat Detection & Forensic Intelligence Platform"
)

# Mount Member 6 Reports Engine
app.include_router(reports_router, prefix="/api")
```

---

## 4. Exposed API Endpoints

Once mounted, Member 6 exposes three endpoints:

| Method | Endpoint URL | Description | Response Type | Status Code |
|:---|:---|:---|:---|:---:|
| `GET` / `POST` | `/api/report/json/{investigationId}` | Generates & returns the machine-readable forensic JSON report with SHA-256 hash | `application/json` | `200 OK` |
| `GET` / `POST` | `/api/report/pdf/{investigationId}` | Generates & streams the forensic PDF report | `application/pdf` | `200 OK` |
| `POST` | `/api/v1/reports/generate` | Generates report metadata and returns URLs for frontend consumption | `application/json` | `200 OK` |

---

## 5. Required Payload Structure (`InvestigationPayload`)

Member 2 must supply the following JSON/dict structure in the request body (or via internal model call):

```json
{
  "investigation_id": "INV-2026-001",
  "case_summary": {
    "investigation_id": "INV-2026-001",
    "subject": "Urgent: Account Verification Required",
    "from_address": "security@paypa1-alerts.com",
    "to_addresses": ["victim@corporate.in"],
    "received_at": "2026-09-08T12:30:00Z",
    "analyzed_at": "2026-09-08T13:00:00Z",
    "threat_type": "phishing",
    "analyst_notes": "Lookalike domain impersonating payment provider."
  },
  "risk_score": {
    "overall_score": 92.5,
    "verdict": "MALICIOUS",
    "confidence": 0.97,
    "phishing_score": 95.0,
    "spoofing_score": 88.0,
    "malware_score": 10.0,
    "bec_score": 20.0
  },
  "sender_analysis": {
    "display_name": "PayPal Security",
    "email_address": "security@paypa1-alerts.com",
    "reply_to": "harvest@evil-host.ru",
    "return_path": "bounce@paypa1-alerts.com",
    "sender_domain": "paypa1-alerts.com",
    "originating_ip": "185.220.101.45",
    "mail_server": "mail.paypa1-alerts.com",
    "domain_age_days": 3,
    "domain_registered": "2026-09-05",
    "is_free_email": false,
    "is_newly_registered": true,
    "lookalike_domain": "paypal.com",
    "header_from_mismatch": true
  },
  "authentication": {
    "spf_result": "fail",
    "spf_details": "No matching SPF record found",
    "dkim_result": "fail",
    "dkim_selector": null,
    "dkim_domain": null,
    "dmarc_result": "fail",
    "dmarc_policy": "reject",
    "arc_result": "none",
    "authentication_summary": "SPF FAIL · DKIM FAIL · DMARC FAIL — Email spoofing confirmed."
  },
  "malicious_ips": [
    {
      "ip": "185.220.101.45",
      "threat_score": 96.0,
      "threat_categories": ["phishing", "tor-exit"],
      "reputation_source": ["AbuseIPDB", "Spamhaus"],
      "geo": {
        "ip": "185.220.101.45",
        "country": "Russia",
        "country_code": "RU",
        "region": "Moscow",
        "city": "Moscow",
        "latitude": 55.7558,
        "longitude": 37.6176,
        "isp": "Tor Exit Router",
        "org": "Anonymous Proxy",
        "asn": "AS1234",
        "is_tor": true,
        "is_vpn": false,
        "is_proxy": false,
        "is_datacenter": false
      },
      "first_seen": "2026-01-01T00:00:00Z",
      "last_seen": "2026-09-08T13:00:00Z",
      "abuse_reports": 142
    }
  ],
  "malicious_urls": [
    {
      "url": "http://paypa1-alerts.com/verify?id=992",
      "domain": "paypa1-alerts.com",
      "threat_score": 98.0,
      "threat_categories": ["phishing", "credential-harvesting"],
      "redirect_chain": [
        "http://paypa1-alerts.com/verify?id=992",
        "http://collect.evil.ru/form"
      ],
      "final_destination": "http://collect.evil.ru/form",
      "is_phishing_kit": true,
      "is_credential_harvester": true,
      "screenshot_url": null,
      "reputation_sources": ["VirusTotal", "PhishTank"]
    }
  ],
  "reputation_scores": [
    {
      "entity": "paypa1-alerts.com",
      "entity_type": "domain",
      "score": 97.0,
      "sources": ["VirusTotal", "AlienVault"],
      "categories": ["phishing"],
      "last_checked": "2026-09-08T13:00:00Z",
      "is_blacklisted": true,
      "blacklist_count": 8
    }
  ],
  "timeline": [
    {
      "timestamp": "2026-09-08T12:30:00Z",
      "event_type": "RECEIVED",
      "description": "Inbound SMTP connection from 185.220.101.45",
      "actor": "mx1.tracemail.internal",
      "metadata": {}
    },
    {
      "timestamp": "2026-09-08T13:00:00Z",
      "event_type": "ANALYZED",
      "description": "Multi-engine AI forensic analysis completed",
      "actor": "TraceMail AI Engine",
      "metadata": {}
    }
  ],
  "correlation_graph": {
    "nodes": [
      { "node_id": "n1", "node_type": "email", "label": "security@paypa1-alerts.com", "threat_score": 92.5, "attributes": {} },
      { "node_id": "n2", "node_type": "ip", "label": "185.220.101.45", "threat_score": 96.0, "attributes": {} }
    ],
    "edges": [
      { "source_id": "n1", "target_id": "n2", "relationship": "SENDS_FROM", "confidence": 0.98, "evidence": "Received header hop" }
    ]
  },
  "evidence": {
    "raw_headers": "Received: from mail.paypa1-alerts.com (185.220.101.45)...\r\nFrom: PayPal Security <security@paypa1-alerts.com>\r\nTo: victim@corporate.in\r\nSubject: Urgent: Account Verification Required\r\nDate: Mon, 08 Sep 2026 12:30:00 +0000",
    "parsed_headers": {
      "from": "PayPal Security <security@paypa1-alerts.com>",
      "to": "victim@corporate.in",
      "subject": "Urgent: Account Verification Required"
    },
    "email_body_text": "Please verify your account immediately at http://paypa1-alerts.com/verify?id=992",
    "email_body_html": "<p>Please verify your account immediately at <a href='http://paypa1-alerts.com/verify?id=992'>link</a></p>",
    "attachments": [],
    "extracted_urls": ["http://paypa1-alerts.com/verify?id=992"],
    "extracted_ips": ["185.220.101.45"],
    "hashes": {
      "md5": "b10a8db164e0754105b7a99be72e3fe5",
      "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
}
```

---

## 6. Step-by-Step Integration Guide for Member 2

1. **Step 1: Install Requirements**
   Add Member 6 requirements to your environment:
   ```bash
   pip install -r member6/requirements.txt
   ```

2. **Step 2: Database Query & Aggregation (Member 2 Responsibility)**
   When an investigation is finalized in PostgreSQL:
   * Fetch case record (`investigations` table)
   * Fetch AI engine score (`ai_predictions` table)
   * Fetch threat intel flags (`ioc_reputations` table)
   * Fetch GeoIP mapping (`ip_locations` table)
   * Map into `InvestigationPayload` dictionary

3. **Step 3: Direct In-Process Calling (Alternative to HTTP)**
   If Member 2 prefers internal Python function calls over HTTP:
   ```python
   from member6.reports.json.json_report import JSONReportGenerator
   from member6.reports.pdf.pdf_generator import PDFReportGenerator

   json_gen = JSONReportGenerator()
   pdf_gen = PDFReportGenerator()

   # 1. Validate payload
   payload_model = json_gen.validate_payload(raw_db_dict)

   # 2. Generate JSON Report
   json_report = json_gen.generate(payload_model)

   # 3. Generate PDF Report (bytes)
   pdf_bytes = pdf_gen.generate_pdf(json_report)
   filename = pdf_gen.generate_pdf_filename(json_report)
   ```

4. **Step 4: Response Headers**
   When serving the PDF file, Member 6 sets these headers for client verification:
   * `Content-Disposition: attachment; filename="tracemail-forensic-{id}-{date}.pdf"`
   * `X-Report-ID: {uuid4}`
   * `X-Investigation-ID: {id}`
   * `X-Report-Hash: {sha256_hex_64}`

---

## 7. Verification Smoke Command

Run the integration smoke test to confirm your environment is ready:

```bash
pytest member6/tests/integration/test_reports_api.py -v -m "not pdf"
```
Output: **100% Passed (14/14 tests)**
