# 🛡️ TraceMail AI

> **"Trace. Analyze. Investigate. Protect."**  
> AI-powered Email Threat Intelligence & Digital Forensics Platform for phishing detection, spoofing analysis, and header tracing.  
> **Smart India Hackathon 2026 (SIH26106)** | Category: *Cybersecurity + AI + Digital Forensics*

---

## 🎯 Executive Overview

**TraceMail AI** is an enterprise-grade cyber defense platform engineered for **CERT-In, Cyber Police/Cyber Cells, SOC analysts, and enterprise incident response teams**. It ingests suspicious emails (`.eml` files or raw headers), autonomously traces the full transmission hop path, validates domain authenticity, enriches indicators of compromise (IOCs) across global threat databases, performs AI-driven phishing analysis, and produces court-admissible forensic reports.

---

## 🏗️ System Architecture & Data Pipeline

```
                              [ Suspicious Email (.eml) / Raw Headers ]
                                                 │
                                                 ▼
                                     ┌───────────────────────┐
                                     │  Next.js 15 Dashboard │  (Frontend Team)
                                     └───────────┬───────────┘
                                                 │ POST /api/investigations
                                                 ▼
                                     ┌───────────────────────┐
                                     │  FastAPI Backend Hub  │  (Backend Team)
                                     └───────────┬───────────┘
                         ┌───────────────────────┼───────────────────────┐
                         ▼                       ▼                       ▼
              ┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
              │ Threat Intelligence │ │      AI Engine      │ │     Maps Engine     │
              │  & Integration Team │ │    (AI Team)        │ │    (Maps Team)      │
              └──────────┬──────────┘ └──────────┬──────────┘ └──────────┬──────────┘
                         │                       │                       │
                         │ • VirusTotal API v3   │ • Phishing Classifier │ • Hop GeoJSON
                         │ • AbuseIPDB v2        │ • LLaMA-3 Explainer   │ • Attack Graph
                         │ • DNS SPF/DKIM/DMARC  │ • Entity Extractor    │ • Server Timeline
                         │ • WHOIS Domain Age    │                       │
                         │ • Geolocation / ASN   │                       │
                         │ • Threat Scorer (0-100)                       │
                         └───────────────────────┼───────────────────────┘
                                                 │
                                                 ▼
                                     ┌───────────────────────┐
                                     │     Reports Engine    │  (Reports Team)
                                     │  Downloadable PDF/JSON│
                                     └───────────────────────┘
```

---

---

## 👥 Project Team & Contributors

> Meet the contributors building TraceMail AI: see the full [**Team Contributors Board with Photos**](docs/CONTRIBUTORS.md).

| # | Role / Module | Module Owned | Primary Folder | Tech Stack |
|---|---------------|--------------|----------------|------------|
| 1 | **Frontend Team** | Dashboard & UI Lead | `frontend/` | Next.js 15 (App Router), Tailwind CSS, shadcn/ui |
| 2 | **Backend Team** | Hub Architecture & Database | `backend/` | FastAPI, PostgreSQL 16, SQLAlchemy, Redis |
| 3 | **AI Engine Team** | Phishing Detection & LLM | `ai-engine/` | Hugging Face Transformers, Groq API (LLaMA 3) |
| 4 | **Threat Intelligence Team** | Cybersecurity & Integration | `threat_intelligence/`, `shared/`, `scripts/` | Python 3.12, VirusTotal, AbuseIPDB, dnspython, whois |
| 5 | **Maps & Attack Graph Team** | Spatial & Graph Visualization | `maps-engine/` | Leaflet GeoJSON, Recharts, Neo4j Graph |
| 6 | **Reports & Forensics Team** | Digital Forensics Reports | `reports/`, `docs/` | WeasyPrint / ReportLab PDF generator |

---

## 📚 Project Documentation

- 👥 [**Team Contributors & Responsibilities**](docs/CONTRIBUTORS.md)
- 📡 [**REST API Specification**](docs/API.md)
- 🛠️ [**Setup & Installation Guide**](docs/SETUP.md)
- 🔀 [**Git Branching & Development Workflow**](docs/WORKFLOW.md)
- 🛡️ [**Security Architecture & Standards**](docs/SECURITY.md)
- 🏛️ [**Master Architecture & Contracts**](ARCHITECTURE.md)


## ⚡ Quickstart Guide

### Option 1: Automated Local Setup (Recommended)

#### Windows (PowerShell):
```powershell
# 1. Run automated setup (creates virtual environment & installs dependencies)
.\scripts\setup\setup.ps1

# 2. Seed realistic demo phishing test cases
python .\scripts\database\seed_database.py

# 3. Run master integration & contract test suite
python .\scripts\testing\integration_test.py

# 4. Start Threat Intelligence microservice on port 8001
.\scripts\deployment\start.ps1
```

#### Linux / macOS (Bash):
```bash
chmod +x scripts/**/*.sh
./scripts/setup/setup.sh
python3 scripts/database/seed_database.py
python3 scripts/testing/integration_test.py
./scripts/deployment/start.sh
```

### Option 2: Full-Stack Docker Compose Orchestration

```bash
# Boot the entire stack (PostgreSQL, Neo4j, Threat Intel, Backend, AI, Frontend)
docker compose up --build -d

# Verify all services are healthy
docker compose ps
```

- **Threat Intelligence API & Swagger**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **FastAPI Hub API & Swagger**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Next.js 15 Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Neo4j Graph Browser**: [http://localhost:7474](http://localhost:7474)

---

## 🔒 Master API Contracts (Section 6 Compliance)

All inter-module communication is locked to the Master API Contract:

### 1. `GET /api/threat/ip/{ip}`
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

### 2. `POST /api/threat/url`
```json
// Request: { "url": "http://paypa1-secure.com/login" }
// Response:
{
  "url": "http://paypa1-secure.com/login",
  "malicious": true,
  "category": "phishing",
  "scanDate": "2026-09-06T10:00:00Z",
  "vtPositives": 14,
  "vtTotal": 90
}
```

### 3. `POST /api/threat/auth-check`
```json
// Request: { "rawHeaders": "Received: from ... \nAuthentication-Results: ..." }
// Response:
{
  "spf": "fail",
  "dkim": "fail",
  "dmarc": "fail",
  "domainAge": "14 days",
  "registrar": "NameCheap Inc."
}
```

### 4. Composite Threat Report (Integration Output Contract)
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

## 🌿 Frozen Git Branch Strategy

```
main                     🔒 Protected (Production / Demo-ready only)
│
└── develop              👑 Integration Branch (Daily team merges)
      │
      ├── feature/frontend-ui
      ├── feature/backend-api
      ├── feature/ai-engine
      ├── feature/threat-intelligence   <-- [Threat Intelligence & Integration Branch]
      └── feature/maps-reports
```

---

## 🧪 Testing & Verification

Run the automated contract and unit tests:
```bash
python scripts/testing/run_all_tests.py
python scripts/testing/integration_test.py
```

---

## 📜 License
Licensed under the MIT License. See [LICENSE](LICENSE) for details.
