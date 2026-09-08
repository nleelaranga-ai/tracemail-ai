# MEMBER6_HANDOFF.md — TraceMail AI (SIH26106)
## Forensic Intelligence Platform — Member 6 Engineering Handoff
**Author:** Member 6 (Reports, QA & Testing, CI/CD, Docker, and System Integrity)  
**Target Audience:** Member 1 (Frontend), Member 2 (Backend), Member 3 (AI Engine), Member 4 (Threat Intel), Member 5 (Maps Engine)  
**Date:** September 2026  
**Status:** 100% Implemented, Hardened & Validated  

---

## 1. Executive Summary: What Member 6 Completed

Member 6 has completed the entire end-to-end forensic reporting, system test harness, continuous integration/deployment pipeline, containerization, and schema contracts for **TraceMail AI** under Problem Statement **SIH26106**.

### Deliverable Modules
1. **Forensic Reports Engine (`member6/reports/`)**:
   * **JSON Engine (`json_report.py`)**: Generates RFC-compliant, machine-readable JSON forensic intelligence reports encompassing all 10 mandated sections with SHA-256 cryptographic tamper-evident hashing.
   * **PDF Engine (`pdf_generator.py`)**: Generates court-admissible, executive-ready forensic PDF reports utilizing WeasyPrint and Jinja2 templating with dark-mode tactical print stylesheets, page numbering, running headers, and zero-trust SSRF protections.
   * **Schema & Drift Exporter (`report_schema.py`)**: Draft-07 JSON Schema exporter and automated CI drift detector.
   * **FastAPI Router (`reports_router.py`)**: Asynchronous, thread-safe endpoints with non-blocking threadpool offloading.
2. **Comprehensive QA & Testing Suite (`member6/tests/`)**:
   * **Unit Tests (`tests/unit/`)**: 69 test cases validating models, risk score boundaries, email authentication parsers, and sanitization.
   * **Integration Tests (`tests/integration/`)**: 27 test cases exercising the full payload-to-report pipeline and ASGI router calls.
   * **Contract Tests (`tests/contract/`)**: 43 contract validation tests guaranteeing zero schema drift across all response fields.
   * **Playwright E2E Suite (`tests/e2e/`)**: 24 multi-browser browser tests verifying real-world API smoke health and UI download workflows.
3. **CI/CD Pipelines (`.github/workflows/`)**:
   * `ci.yml`: 8-job continuous integration pipeline running linters (Ruff, Mypy, TSC), test suites, coverage threshold gates (>=80%), schema drift validation, Docker multi-stage builds, and Playwright smoke checks.
   * `pr-checks.yml`: PR status gate blocking merges if tests fail and publishing automated markdown summaries to PR comments.
4. **Docker Container Stack (`member6/docker/`)**:
   * Production multi-stage `Dockerfile.backend` with GTK/Pango/Cairo system libraries.
   * Multi-stage `Dockerfile.frontend` standalone image.
   * Orchestrated 7-service `docker-compose.yml` (PostgreSQL, Redis, Backend, Frontend, AI Stub, Threat Intel Stub, Maps Stub).
5. **Contract & Architecture Documentation (`member6/docs/`)**:
   * `ARCHITECTURE.md`, `API_CONTRACTS.md`, and `integration_checklist.md`.

---

## 2. API Endpoints Exposed

The Reports Engine is mounted on the backend under the `/api` prefix:

| HTTP Method | Route URL | Purpose | Request Body | Response Format | Status Codes |
|:---|:---|:---|:---|:---|:---:|
| `GET` / `POST` | `/api/report/json/{investigationId}` | Export machine-readable forensic report | `InvestigationPayload` (JSON) | `application/json` | `200`, `400`, `422`, `500` |
| `GET` / `POST` | `/api/report/pdf/{investigationId}` | Stream downloadable forensic PDF | `InvestigationPayload` (JSON) | `application/pdf` | `200`, `400`, `422`, `500` |
| `POST` | `/api/v1/reports/generate` | Generate both report URLs | `InvestigationPayload` (JSON) | `application/json` | `200`, `422` |

### Streaming PDF Response Headers
When `GET /api/report/pdf/{investigationId}` is invoked, the response includes:
* `Content-Type: application/pdf`
* `Content-Disposition: attachment; filename="tracemail-forensic-{id}-{YYYYMMDD}.pdf"`
* `X-Report-ID: {UUIDv4}`
* `X-Investigation-ID: {investigationId}`
* `X-Report-Hash: {64-character SHA-256 string}`

---

## 3. Docker Commands

### One-Command Full Stack Startup
```bash
# Start all core services (PostgreSQL, Redis, Backend + Reports Engine, AI/Intel/Maps stubs)
docker compose -f member6/docker/docker-compose.yml up --build -d

# Verify all services are healthy
docker compose -f member6/docker/docker-compose.yml ps

# View live backend logs
docker compose -f member6/docker/docker-compose.yml logs -f backend

# Stop stack
docker compose -f member6/docker/docker-compose.yml down
```

### Build & Run Backend Standalone
```bash
# Build standalone Docker image
docker build -f member6/docker/Dockerfile.backend -t tracemail-backend .

# Run standalone backend container
docker run -d -p 8000:8000 --name tracemail-api tracemail-backend
```

---

## 4. CI/CD Workflow Details

### Master CI Pipeline (`.github/workflows/ci.yml`)
Triggers on pushes to `main`, `develop`, and all PRs. Runs 8 parallel jobs:
1. `lint-python`: Ruff formatting & linter + Mypy strict type checking.
2. `lint-typescript`: TypeScript compilation check (`tsc --noEmit`) for E2E tests.
3. `test-unit`: Pytest unit tests + coverage report (enforces >= 80% coverage).
4. `test-integration`: Tests FastAPI router endpoints with ASGI TestClient.
5. `test-contract`: Verifies that API responses strictly conform to Draft-07 JSON Schema.
6. `schema-drift`: Runs `python -m member6.reports.schemas.report_schema --check-drift`. Exits 1 if Pydantic models change without updating `report_schema.json`.
7. `docker-build`: Tests compilation of backend and frontend multi-stage Dockerfiles.
8. `e2e-api-smoke`: Boots backend container and runs Playwright smoke tests.

---

## 5. How Members 1-5 Must Integrate

### Architecture Rule (SIH Mandate)
> **The Reports Module never queries the database directly.**
> All report generation is on-demand. The backend assembles data from PostgreSQL and delivers it as an `InvestigationPayload`.

### Integration Matrix by Member

#### Member 1: Frontend Lead
* **Triggering PDF Downloads**:
  Call `GET /api/report/pdf/{investigationId}` or trigger via direct browser download:
  ```typescript
  const downloadPdf = (investigationId: string) => {
    window.open(`/api/report/pdf/${investigationId}`, '_blank');
  };
  ```
* **Embedding Report Metadata**:
  Call `GET /api/report/json/{investigationId}` to receive the SHA-256 hash, forensic indicators, and verdict breakdown for dashboard widgets.

#### Member 2: Backend API Lead
* **Mounting the Reports Router**:
  In `app/main.py`:
  ```python
  from fastapi import FastAPI
  from member6.reports.router.reports_router import reports_router

  app = FastAPI(title="TraceMail AI")
  app.include_router(reports_router, prefix="/api")
  ```
* **Assembling `InvestigationPayload`**:
  Query your database tables:
  1. `investigations` -> Case Summary & Evidence
  2. `ai_predictions` -> Risk Score & Verdict (Member 3)
  3. `ioc_reputations` -> Reputation Scores & Threat Types (Member 4)
  4. `ip_locations` -> GeoLocation & Malicious IPs (Member 5)
  Format as a dictionary matching `InvestigationPayload` and pass to the router.

#### Member 3: AI Engine Lead
* Provide numeric sub-scores:
  * `phishing_score` (0.0 to 100.0)
  * `spoofing_score` (0.0 to 100.0)
  * `malware_score` (0.0 to 100.0)
  * `bec_score` (0.0 to 100.0)
  * `confidence` (0.0 to 1.0)
  * `verdict` (`"MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN"`)

#### Member 4: Threat Intelligence Lead
* Supply IOC indicator lists:
  * `malicious_ips`: list of `{ ip, threat_score, threat_categories, reputation_source, abuse_reports }`
  * `malicious_urls`: list of `{ url, domain, threat_score, redirect_chain, is_phishing_kit, is_credential_harvester }`
  * `reputation_scores`: list of `{ entity, entity_type, score, is_blacklisted, blacklist_count }`

#### Member 5: Maps & GeoLocation Lead
* Populate the `geo` field inside `MaliciousIP`:
  * `{ ip, country, country_code, region, city, latitude, longitude, isp, org, asn, is_tor, is_vpn, is_proxy, is_datacenter }`

---

## 6. Common Troubleshooting Steps

### 1. `ModuleNotFoundError: No module named 'member6'`
* **Root Cause**: Working directory or `PYTHONPATH` not set.
* **Resolution**: Run commands from the repository root, or set `pythonpath = .` in `pytest.ini` (already configured). In Python scripts:
  ```bash
  export PYTHONPATH=.
  ```

### 2. WeasyPrint `RuntimeError: WeasyPrint is not installed` or OS Library Error
* **Root Cause**: Missing native Cairo/Pango C-libraries on host Windows/macOS.
* **Resolution**:
  * Option A (Recommended): Run via Docker (`docker compose up --build`). The Linux image has `libpango-1.0-0` and `libcairo2` pre-installed.
  * Option B: Run pytest with `-m "not pdf"` to execute all 132 logical tests without needing WeasyPrint.

### 3. Schema Drift Test Failure in CI
* **Root Cause**: A team member modified Pydantic models in `json_report.py` without updating `report_schema.json`.
* **Resolution**: Regenerate the schema and commit:
  ```bash
  python -m member6.reports.schemas.report_schema
  git add member6/reports/schemas/report_schema.json
  git commit -m "chore: sync report schema"
  ```

### 4. `422 Unprocessable Entity` on Report Endpoints
* **Root Cause**: `investigation_id` in URL does not match `case_summary.investigation_id` in request body.
* **Resolution**: Ensure the URL path variable `{investigationId}` exactly matches the ID inside the payload dictionary.
