## Pull Request Overview

**Module Affected**:
- [ ] `frontend/` (Frontend Team)
- [ ] `backend/` (Backend Team)
- [ ] `ai-engine/` (AI Engine Team)
- [ ] `threat-intelligence/` (Threat Intelligence Team)
- [ ] `maps-engine/` (Maps & Attack Graph Team)
- [ ] `reports/` (Reports & Forensics Team)
- [ ] `shared/` (Threat Intelligence & Integration Team)
- [ ] `docker/` or `.github/` (DevOps & Integration)

---

### Mandatory Pre-Merge Checklist (TraceMail AI Engineering Standards)
- [ ] I branched from `develop` and am targeting `develop` (never `main` directly).
- [ ] I only modified files within my assigned folder ownership.
- [ ] All request/response payloads strictly match **Section 6 Master API Contracts**.
- [ ] No hardcoded API keys or secrets are committed.
- [ ] All unit and contract tests pass locally (`python scripts/testing/run_all_tests.py`).
- [ ] `python scripts/testing/integration_test.py` passes without schema errors.

---

### Description of Changes
1. ...
2. ...

### Verification Output / Screenshots
Attach output of `run_all_tests.py` or `integration_test.py` or UI screenshots.
