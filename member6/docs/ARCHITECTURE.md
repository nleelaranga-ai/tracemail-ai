# TraceMail AI — System Architecture
## SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence

---

## Overview

TraceMail AI is a six-member SIH project that provides forensic-grade email threat analysis using artificial intelligence, threat intelligence feeds, and geolocation mapping.

```
┌─────────────────────────────────────────────────────────────────┐
│                        TraceMail AI Platform                    │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│   Frontend   │   Backend    │  AI Engine   │  Reports Engine    │
│  (Next.js)   │  (FastAPI)   │ (Phishing)   │  (Member 6 / PDF)  │
│  Port: 3000  │  Port: 8000  │  Port: 8001  │  Port: 8004        │
└──────┬───────┴──────┬───────┴──────┬───────┴────────┬───────────┘
       │              │              │                │
       │         ┌────┴────┐   ┌─────┴──────┐         │
       │         │Threat   │   │Maps Engine │         │
       │         │Intel    │   │(GeoIP)     │         │
       │         │Port:8002│   │Port: 8003  │         │
       │         └─────────┘   └────────────┘         │
       │                                              │
       └──────────────── PostgreSQL :5432 ────────────┘
                         Redis :6379
```

---

## Component Responsibilities

| Member | Component | Port | Technology |
|--------|-----------|------|-----------|
| 1 | Frontend | 3000 | Next.js + Tailwind |
| 2 | Backend API | 8000 | FastAPI + PostgreSQL |
| 3 | AI Engine | 8001 | Python ML / Phishing Detection |
| 4 | Threat Intelligence | 8002 | VirusTotal / AbuseIPDB integrations |
| 5 | Maps Engine | 8003 | GeoIP + Leaflet |
| **6** | **Reports Engine + QA + CI/CD + Docker + Docs** | **8004** | **WeasyPrint + pytest + Playwright + GitHub Actions** |

---

## Member 6 Architecture

```
member6/
├── reports/              # Reports Engine
│   ├── json/             # JSON report generator (Pydantic → structured JSON)
│   ├── pdf/              # PDF generator (Jinja2 + WeasyPrint)
│   ├── schemas/          # JSON Schema Draft-07 (validation + drift detection)
│   ├── templates/        # HTML+CSS report template (10 sections)
│   └── router/           # FastAPI router (3 endpoints)
│
├── tests/                # QA & Testing
│   ├── unit/             # pytest unit tests (json, pdf, models)
│   ├── integration/      # ASGI integration tests (httpx + TestClient)
│   ├── contract/         # Schema contract tests (JSON Schema validation)
│   └── e2e/              # Playwright TypeScript E2E tests
│
├── docker/               # Docker
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
│
└── docs/                 # Documentation
```

---

## Data Flow: Report Generation

```
User (Frontend)
    │
    │ GET /api/report/pdf/{investigationId}
    ▼
Backend FastAPI
    │
    │ 1. Retrieve investigation from DB
    │ 2. Assemble InvestigationPayload
    │    (aggregates AI + ThreatIntel + Maps results)
    │
    ▼
Reports Engine (Member 6)
    │
    │ 3. Validate InvestigationPayload (Pydantic)
    │ 4. JSONReportGenerator.generate(payload) → JSONReport
    │ 5. PDFReportGenerator.generate_pdf(report) → bytes
    │
    ▼
StreamingResponse → User downloads PDF
```

> **Key constraint**: The Reports Engine NEVER queries the database directly.
> All data arrives pre-assembled from the Backend.

---

## Report Sections (10 Required)

1. Case Summary
2. Risk Score & Verdict
3. Sender Analysis
4. SPF / DKIM / DMARC Results
5. Malicious IPs (with GeoLocation)
6. Malicious URLs (with redirect chain)
7. Reputation Scores
8. Timeline (chronologically sorted)
9. Correlation Graph (nodes + edges)
10. Investigation Evidence (raw headers, hashes, extracted IoCs)

---

## Technology Stack (Member 6)

```
Reports Engine:
  - Python 3.12
  - Pydantic v2          (data validation + schema generation)
  - WeasyPrint           (HTML → PDF)
  - Jinja2               (HTML templating)
  - jsonschema           (Draft-07 validation)
  - FastAPI              (REST endpoints)

Testing:
  - pytest 8.x           (unit + integration + contract)
  - httpx                (async ASGI test client)
  - Playwright 1.47 (TS) (E2E browser + API tests)

CI/CD:
  - GitHub Actions       (ci.yml + pr-checks.yml)
  - ruff                 (Python linting)
  - mypy                 (type checking)

Docker:
  - Docker Compose v3.9  (full stack)
  - Multi-stage builds   (backend + frontend)
```
