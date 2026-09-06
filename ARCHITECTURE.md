# TraceMail AI — System Architecture Specification
**Document Version**: 1.0.0 (Master Engineering Architecture)  
**Problem Statement**: Smart India Hackathon 2026 (SIH26106)  
**Target Users**: CERT-In, State Cyber Police / Cyber Crime Cells, SOC Analysts, Enterprise Security Teams  
**Lead Author**: Threat Intelligence & Integration Team

---

## 1. Executive Summary & Vision

Email remains the primary initial attack vector in >80% of sophisticated cyber incidents, including BEC (Business Email Compromise), CEO spoofing, ransomware distribution, and credential harvesting. 

**TraceMail AI** solves this critical challenge by acting as an automated digital forensics unit:
1. **Header Deconstruction**: Parses RFC 822 / MIME email headers down to individual `Received` hops.
2. **Identity & Authentication Verification**: Validates SPF, DKIM, and DMARC alignment against the declared sender domain and uncovers fake `From` headers.
3. **Multi-Source Threat Enrichment**: Queries global threat intelligence feeds (VirusTotal, AbuseIPDB, URLScan, WHOIS domain age, and IP geolocation) to rate the reputation of every relay hop and extracted link.
4. **AI Behavioral Phishing Analysis**: Applies natural language models to the email body to detect urgency, extortion, credential harvesting language, and typosquatting.
5. **Attack Path Visualization**: Transforms IP hop telemetry into a world map, chronological transmission timeline, and an interactive attack graph.
6. **Evidentiary Forensic Reporting**: Automatically compiles a court-admissible PDF forensic dossier with SHA-256 integrity verification.

---

## 2. End-to-End Processing Pipeline

```
[1. User Uploads .eml / Raw Headers]
                  │
                  ▼
[2. Backend Ingestion Hub (FastAPI)]
  ├── Generates unique investigation UUID
  ├── Stores raw content in PostgreSQL (investigations, emails, headers)
  │
  ├──► [3. AI Engine Microservice (Port 8002)]
  │      ├── Extracts body entities (URLs, IPs, domains, claimed sender)
  │      ├── Scores text for phishing / BEC probability (0-100)
  │      └── Returns LLaMA 3.x plain-English evidence explanation
  │
  ├──► [4. Threat Intelligence Engine (Port 8001)]  <-- (Threat Intelligence Team)
  │      ├── Extracts and defangs all IOCs
  │      ├── Validates SPF / DKIM / DMARC authentication
  │      ├── Resolves domain age & registrar via WHOIS
  │      ├── Queries VirusTotal v3 for URL maliciousness
  │      ├── Queries AbuseIPDB v2 for IP abuse confidence
  │      ├── Resolves IP geolocation (Lat/Lon/City/Country/ISP/ASN)
  │      └── Calculates composite threat score (0-100)
  │
  ├──► [5. Maps & Attack Graph Engine (Port 7474)]
  │      ├── Generates GeoJSON FeatureCollection of relay hops
  │      ├── Orders chronological hop timeline
  │      └── Constructs Node/Edge attack graph (Sender -> Relay1 -> Relay2 -> Recipient)
  │
  └──► [6. Reports Engine (On-Demand)]
         ├── Compiles assembled investigation data into PDF dossier
         └── Emits structured JSON export for CERT-In automated ingestion
```

---

## 3. Module Responsibilities & Folder Boundaries

| Folder | Module | Lead Team | Responsibilities |
|---|---|---|---|
| `threat_intelligence/` | Threat Intelligence | **Threat Intelligence Team** | VirusTotal, AbuseIPDB, WHOIS, DNS/Auth, Geolocation, URLScan, IOC extraction, Threat Scoring. |
| `shared/` | Shared Contracts & Layer | **Threat Intelligence Team** | Pydantic contracts, TypeScript types, validators, centralized settings, logging, and enums. |
| `scripts/` | Automation & Tooling | **Threat Intelligence Team** | Setup scripts, seeders, reset utilities, master integration test runner. |
| `docker/` | Container Infrastructure | **Threat Intelligence & Backend Teams** | Multi-service Dockerfiles and root `docker-compose.yml`. |
| `.github/` | CI/CD Infrastructure | **Threat Intelligence Team** | GitHub Actions workflows (`ci.yml`), PR templates, Issue templates, CODEOWNERS. |
| `backend/` | Backend Hub & Database | **Backend Team** | PostgreSQL schema, Prisma/SQLAlchemy models, auth, orchestration pipeline. |
| `frontend/` | Web Dashboard | **Frontend Team** | Next.js 15 App Router, Tailwind CSS, shadcn/ui, Leaflet map, attack graph UI. |
| `ai-engine/` | AI Phishing Classifier | **AI Engine Team** | Transformers phishing model, LLaMA-3 explainer via Groq API. |
| `maps-engine/` | Visualization Data | **Maps & Attack Graph Team** | GeoJSON hop builder, timeline builder, attack graph node/edge generator. |
| `reports/` | Digital Forensics Reports | **Reports & Forensics Team** | PDF generation (ReportLab / WeasyPrint) and JSON export. |

---

## 4. Master API Contracts Specification (Section 6)

### 4.1 IP Threat Enrichment
- **Endpoint**: `GET /api/threat/ip/{ip}`
- **Owner**: Threat Intelligence Team
- **Consumers**: Backend Hub (Backend Team), Maps Engine (Maps Team)
- **Response Schema**:
```json
{
  "ip": "185.220.101.4",
  "country": "Germany",
  "city": "Frankfurt",
  "lat": 50.1109,
  "lon": 8.6821,
  "isp": "M247 Ltd",
  "asn": "AS9009",
  "abuseScore": 92,
  "malicious": true
}
```

### 4.2 URL Reputation Scan
- **Endpoint**: `POST /api/threat/url`
- **Owner**: Threat Intelligence Team
- **Consumers**: Backend Hub (Backend Team), AI Engine (AI Team), Reports (Reports Team)
- **Request Schema**:
```json
{
  "url": "http://paypa1-secure.com/login"
}
```
- **Response Schema**:
```json
{
  "url": "http://paypa1-secure.com/login",
  "malicious": true,
  "category": "phishing",
  "scanDate": "2026-09-06T10:00:00Z",
  "vtPositives": 14,
  "vtTotal": 90
}
```

### 4.3 Email Authentication & WHOIS Validation
- **Endpoint**: `POST /api/threat/auth-check`
- **Owner**: Threat Intelligence Team
- **Consumers**: Backend Hub (Backend Team), Reports Engine (Reports Team)
- **Request Schema**:
```json
{
  "rawHeaders": "Received: from ... \nAuthentication-Results: ..."
}
```
- **Response Schema**:
```json
{
  "spf": "fail",
  "dkim": "fail",
  "dmarc": "fail",
  "domainAge": "14 days",
  "registrar": "NameCheap Inc."
}
```

### 4.4 Composite Threat Intelligence Summary (Integration Output Contract)
- **Endpoint**: `POST /api/threat/composite`
- **Owner**: Threat Intelligence Team
- **Consumers**: Backend Hub (Backend Team)
- **Response Schema**:
```json
{
  "risk_level": "HIGH",
  "risk_score": 94,
  "malicious_url": true,
  "domain_age_days": 12,
  "ip_reputation": 98,
  "country": "Germany",
  "spf": "FAIL",
  "dkim": "PASS",
  "dmarc": "FAIL"
}
```

---

## 5. Threat Intelligence Scoring Formula

The threat engine computes a composite threat score from 0 to 100 based on weighted signals:

$$\text{Composite Score} = S_{\text{auth}} + S_{\text{domain\_age}} + S_{\text{ip\_abuse}} + S_{\text{url}} + S_{\text{spoof}}$$

Where:
- **$S_{\text{auth}}$ (Up to 40 pts)**:
  - SPF Fail = +15 pts
  - DKIM Fail = +10 pts
  - DMARC Fail = +15 pts
- **$S_{\text{domain\_age}}$ (Up to 25 pts)**:
  - $\le 14$ days = +25 pts
  - $\le 30$ days = +15 pts
  - $\le 90$ days = +5 pts
- **$S_{\text{ip\_abuse}}$ (Up to 30 pts)**:
  - $\text{Max AbuseIPDB Score} \times 0.30$
- **$S_{\text{url}}$ (Up to 35 pts)**:
  - Malicious URL detected = +25 pts
  - Security vendor detections $\ge 5$ = +10 pts
- **$S_{\text{spoof}}$ (Up to 15 pts)**:
  - Claimed vs Actual Sender address discrepancy = +15 pts

Normalized Classification:
- **0 - 29**: `SAFE` (Green)
- **30 - 69**: `SUSPICIOUS` (Amber)
- **70 - 89**: `HIGH` (Red)
- **90 - 100**: `CRITICAL` (Dark Red)

---

## 6. High-Availability & Fallback Design

During hackathons and operational deployments, external security APIs can hit rate limits or experience network dropouts. The Threat Intelligence engine includes:
1. **Multi-Level TTL Caching**: In-memory caching for IP, domain, URL, and WHOIS lookups to prevent repeated queries for identical hops.
2. **Asynchronous Parallel Querying**: `asyncio` execution prevents slow WHOIS queries from blocking fast IP lookups.
3. **Graceful Heuristic Fallbacks**: If external API keys are omitted or rate-limited, the engine activates high-accuracy heuristic scanners (RFC 1918 checks, typosquatting regexes, keyword tokenizers) and returns partial verdicts rather than raising a 500 error.
