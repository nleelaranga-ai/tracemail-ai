# 🔀 TraceMail AI — Git & Development Workflow

To maintain production stability during Smart India Hackathon 2026 development, all contributors adhere to this Git workflow.

---

## 1. Branch Architecture

```
main                     🔒 Protected (Production / Demo-Ready Only)
│
└── develop              👑 Team Integration Branch (Daily PR Merges)
      │
      ├── feature/frontend-ui           (Frontend Team)
      ├── feature/backend-api           (Backend Team)
      ├── feature/ai-engine             (AI Engine Team)
      ├── feature/threat-intelligence   (Threat Intelligence Team)
      ├── feature/maps-engine           (Maps & Graph Team)
      └── feature/reports-engine        (Reports Team)
```

---

## 2. Core Git Rules

1. **Never commit directly to `main` or `develop`**.
2. **Every feature branch must be created from `develop`**.
```bash
# Correct way to start a new feature
git checkout develop
git pull origin develop
git checkout -b feature/<your-feature-name>
```
3. **Pull Requests target `develop`**.
4. **`develop` merges to `main` only before official evaluation and demo**.

---

## 3. Commit Message Standards

Use Conventional Commits syntax:
- `feat(<module>): <description>` — New functionality
- `fix(<module>): <description>` — Bug fix
- `docs(<module>): <description>` — Documentation updates
- `test(<module>): <description>` — Adding or updating test cases
- `refactor(<module>): <description>` — Code improvement without feature change
- `chore(<module>): <description>` — Build, CI/CD, or repo maintenance

### Examples:
```bash
feat(backend): implement jwt authentication router
feat(threat-intel): add abuseipdb confidence score caching
fix(frontend): resolve hydration mismatch in map panel
```
