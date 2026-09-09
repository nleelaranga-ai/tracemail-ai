# TraceMail AI — API Contracts
## SIH26106 | Team Reports — Reports Engine API

All Reports Engine endpoints are mounted under `/api` on the backend (port 8000).

---

## Base URL

```
http://localhost:8000/api
```

---

## Endpoints

### 1. Generate Report Metadata

```
POST /api/v1/reports/generate
```

**Request Body:** `InvestigationPayload` (see Schema below)

**Response 200:**
```json
{
  "investigation_id": "INV-001",
  "reports": {
    "pdf": {
      "url": "/api/report/pdf/INV-001",
      "method": "GET",
      "description": "Downloadable PDF forensic report"
    },
    "json": {
      "url": "/api/report/json/INV-001",
      "method": "GET",
      "description": "Machine-readable JSON forensic report"
    }
  }
}
```

---

### 2. Get JSON Report

```
GET /api/report/json/{investigationId}
```

**URL param:** `investigationId` — the investigation ID  
**Body:** Same `InvestigationPayload` as above  
**Content-Type:** `application/json`

**Response 200:** `JSONReport` (see Report Schema section)

**Errors:**
| Code | Reason |
|------|--------|
| 400 | URL `investigationId` ≠ payload `investigation_id` |
| 422 | Invalid / missing payload fields |
| 500 | Report generation failed |

---

### 3. Get PDF Report

```
GET /api/report/pdf/{investigationId}
```

**URL param:** `investigationId`  
**Body:** Same `InvestigationPayload`  
**Response Content-Type:** `application/pdf`

**Response Headers:**
```
Content-Disposition: attachment; filename="tracemail-forensic-INV-001-20260908.pdf"
X-Report-ID: <uuid>
X-Investigation-ID: INV-001
X-Report-Hash: <sha256-64-char-hex>
```

**Errors:** Same as JSON endpoint.

---

## InvestigationPayload Schema

The backend sends this assembled object to the Reports Engine.

```json
{
  "investigation_id": "string (required)",
  "case_summary": {
    "investigation_id": "string",
    "subject": "string",
    "from_address": "string",
    "to_addresses": ["string"],
    "received_at": "datetime ISO 8601",
    "analyzed_at": "datetime ISO 8601",
    "threat_type": "phishing|malware|spam|spoofing|business_email_compromise|unknown",
    "analyst_notes": "string|null"
  },
  "risk_score": {
    "overall_score": "float 0-100",
    "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN",
    "confidence": "float 0.0-1.0",
    "phishing_score": "float 0-100",
    "spoofing_score": "float 0-100",
    "malware_score": "float 0-100",
    "bec_score": "float 0-100"
  },
  "sender_analysis": { "..." },
  "authentication": {
    "spf_result": "pass|fail|softfail|neutral|none|temperror|permerror",
    "dkim_result": "pass|fail|...",
    "dmarc_result": "pass|fail|...",
    "authentication_summary": "string"
  },
  "malicious_ips": [
    {
      "ip": "string",
      "threat_score": "float 0-100",
      "threat_categories": ["string"],
      "reputation_source": ["string"],
      "geo": { "ip": "string", "country": "string", "is_tor": "bool", "..." },
      "abuse_reports": "int"
    }
  ],
  "malicious_urls": [
    {
      "url": "string",
      "domain": "string",
      "threat_score": "float 0-100",
      "is_phishing_kit": "bool",
      "is_credential_harvester": "bool"
    }
  ],
  "reputation_scores": [{ "entity": "string", "score": "float", "is_blacklisted": "bool" }],
  "timeline": [
    {
      "timestamp": "datetime ISO 8601",
      "event_type": "RECEIVED|FORWARDED|DELIVERED|BLOCKED|ANALYZED",
      "description": "string",
      "actor": "string|null"
    }
  ],
  "correlation_graph": {
    "nodes": [{ "node_id": "string", "node_type": "string", "label": "string", "threat_score": "float" }],
    "edges": [{ "source_id": "string", "target_id": "string", "relationship": "string", "confidence": "float" }]
  },
  "evidence": {
    "raw_headers": "string",
    "parsed_headers": {},
    "email_body_text": "string|null",
    "email_body_html": "string|null",
    "attachments": [],
    "extracted_urls": ["string"],
    "extracted_ips": ["string"],
    "hashes": { "md5": "string", "sha1": "string", "sha256": "string" }
  }
}
```

---

## JSONReport Response Schema

The JSON report adds the following envelope to the InvestigationPayload sections:

```json
{
  "report_id": "uuid-v4",
  "report_version": "1.0.0",
  "generated_at": "datetime ISO 8601",
  "generated_by": "TraceMail AI — Reports Engine v1.0",
  "investigation_id": "string",
  "report_hash": "sha256-64-char-hex",
  "...all 10 investigation sections..."
}
```

The `report_hash` is SHA-256 of all report content excluding `report_id`, `generated_at`, and `report_hash` itself. Use this to verify report integrity.
