# TraceMail AI — Engineering Code Style & Standards

This document establishes the coding conventions, naming standards, and architectural rules for all engineers contributing to **TraceMail AI**.

---

## 🐍 1. Python Standards (Python 3.12+)

All backend, threat intelligence, and AI modules must follow these rules:

### 1.1 Formatting & Style
- Adhere strictly to **PEP 8**.
- Maximum line length: **100 characters**.
- Use 4 spaces for indentation (no tabs).
- Sort imports logically: Standard Library → Third-Party Libraries → Local Modules.

### 1.2 Type Annotations
- **100% Type Annotations**: Every function and method signature must declare parameter types and return types:
  ```python
  async def get_ip_threat(self, ip: str) -> IPThreatResponse:
      ...
  ```
- Use Pydantic v2 `BaseModel` for all external data structures and JSON payloads.
- Avoid raw `dict` returns where a Pydantic schema is specified.

### 1.3 Error Handling & Resilience
- Never use bare `except:` clauses. Always catch specific exceptions (`ValueError`, `HTTPError`, etc.).
- Never let downstream external API failures crash the application. Always catch timeouts and provide fallback verdicts.
- Log failures using `shared.config.logging.get_logger`.

### 1.4 Cybersecurity Defanging
- Whenever logging or storing raw untrusted URLs/domains, use `defang_url()` from `threat_intelligence.indicators.extractor` to avoid accidental clicks:
  ```python
  logger.info(f"Analyzing IOC: {defang_url(malicious_url)}")
  ```

---

## ⚡ 2. TypeScript / Next.js 15 Standards

For frontend development (`frontend/`):
- Use **Strict Mode** in `tsconfig.json`.
- Do not use `any`. Always import or mirror the shared contract types from `shared/types/types.ts`.
- Prefer React Server Components (`RSC`) where applicable; use `'use client'` only for interactive panels (maps, tabs, modals).
- Use Tailwind utility classes; avoid inline styles.

---

## 📁 3. Naming Conventions

| Entity | Python | TypeScript / JavaScript | Database |
|---|---|---|---|
| Variables & Functions | `snake_case` | `camelCase` | `snake_case` |
| Classes & Types | `PascalCase` | `PascalCase` | `PascalCase` |
| Constants | `UPPER_SNAKE_CASE` | `UPPER_SNAKE_CASE` | `UPPER_SNAKE_CASE` |
| Files & Folders | `snake_case.py` | `kebab-case.tsx` | - |
| API Endpoints | `kebab-case` (`/api/threat/auth-check`) | - | - |

---

## 🏷️ 4. Commit Message Format

```
<type>(<scope>): <short summary>

[optional body]
```

- **Allowed Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`.
- **Example**: `feat(threat): implement DNS SPF and DKIM authentication validator`
