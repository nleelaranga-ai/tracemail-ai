# 🛡️ TraceMail AI — Security Architecture & Guidelines

TraceMail AI is designed with cybersecurity and digital forensics standards at its core.

---

## 1. Secrets & Credential Protection

- **Zero Hardcoded Secrets**: No production API keys, passwords, or JWT secrets are ever committed to Git.
- **Environment Isolation**: All configuration is loaded dynamically from `.env` via `shared.config.settings` and `backend.utils.config`.
- **Secret Scanning**: GitHub Secret Scanning and pre-commit hooks ensure `.env` and sensitive files remain gitignored.

---

## 2. Authentication & Authorization

- **JWT (JSON Web Tokens)**: Standard RFC 7519 implementation signed with HMAC-SHA256 (`HS256`).
- **Password Hashing**: Passwords stored in PostgreSQL are hashed using `bcrypt` with adaptive salt rounds.
- **Token Expiration**: Access tokens are configured with a strict 24-hour time-to-live (`TTL`).

---

## 3. Data Ingestion & Sanitization

- **Defanging Indicators**: Malicious URLs and IP addresses are parsed with defanging safeguards (`hxxp://`, `[.]`) to avoid accidental analyst click-throughs.
- **MIME Bomb Prevention**: File upload limits (maximum 10MB per `.eml` file) prevent denial-of-service memory exhaustion.
- **RFC 1918 Private IP Filtering**: Internal, loopback, and private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are suppressed from public threat queries to prevent internal network leakage.

---

## 4. Network & Container Security

- **Non-Root Containers**: Docker containers run under restricted non-privileged user accounts (`useradd -u 10001 tracemail`).
- **Isolated Bridge Network**: Microservices communicate over internal Docker bridge `tracemail-net`, with only required gateway ports exposed to the host.
- **Rate Limiting**: In-memory token bucket rate limiting on `/api/*` endpoints prevents API brute-forcing and quota exhaustion.
