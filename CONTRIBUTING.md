# Contributing to TraceMail AI

Thank you for contributing to **TraceMail AI** (Smart India Hackathon 2026 - SIH26106)! To prevent merge conflicts and ensure seamless multi-module integration across our engineering teams, all developers must strictly adhere to the rules in this document.

---

## 🌿 1. Frozen Git Branch Strategy

```
main                     🔒 Protected (Production / Demo-ready only)
│
└── develop              👑 Daily Integration Branch (PR target)
      │
      ├── feature/frontend-ui           (Frontend Team)
      ├── feature/backend-api           (Backend Team)
      ├── feature/ai-engine             (AI Engine Team)
      ├── feature/threat-intelligence   (Threat Intelligence Team)
      └── feature/maps-reports          (Maps & Reports Teams)
```

### Core Rules:
1. **Never push directly to `main` or `develop`.**
2. **Always branch off `develop`** when starting new work:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/<your-feature-name>
   ```
3. **Open Pull Requests targeting `develop` only.**
4. `develop` is merged into `main` only after full end-to-end integration tests pass.

---

## 📁 2. Strict Folder Ownership

To prevent merge conflicts:
- **Never edit files inside another team's folder** without an explicit Pull Request and review.
- Folder assignments:
  - `frontend/`: Frontend Team
  - `backend/`: Backend Team
  - `ai-engine/`: AI Engine Team
  - `threat_intelligence/`: Threat Intelligence Team
  - `shared/`: Threat Intelligence Team
  - `scripts/`: Threat Intelligence Team
  - `maps-engine/`: Maps & Attack Graph Team
  - `reports/`: Reports & Forensics Team

---

## 🔒 3. API Contracts Are Law (Section 6)

All inter-module communication is bound to the Master API Contracts in `ARCHITECTURE.md`.
- **Never rename or remove request/response JSON fields.**
- If you need a new field, file a GitHub Issue tagged `schema-change` for team agreement before altering code.

---

## 🧪 4. Pre-Commit / Pre-PR Checklist

Before opening a Pull Request into `develop`, verify that:
1. All unit tests pass:
   ```bash
   python scripts/testing/run_all_tests.py
   ```
2. Master API contract tests pass:
   ```bash
   python scripts/testing/integration_test.py
   ```
3. No secrets or API keys are committed in `.env` (use `.env.example` placeholders).
4. Code follows formatting standards defined in `CODE_STYLE.md`.

---

## 💬 5. Commit Message Standards

Use Conventional Commits syntax:
- `feat(threat): add urlscan reputation client`
- `fix(dns): handle missing Authentication-Results header`
- `test(shared): add validation checks for RFC1918 IPs`
- `docs(readme): update quickstart setup instructions`
- `chore(docker): update container healthcheck interval`
