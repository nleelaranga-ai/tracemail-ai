"""
TraceMail AI -- Master Integration & Contract Verification Runner
Threat Intelligence & Integration Team

Validates that all microservice contracts in Section 6 match the exact Pydantic/TypeScript schema.
Can run against a live server or via in-process ASGI TestClient.
"""

import sys
import json
from typing import Dict, Any
from fastapi.testclient import TestClient

# Ensure root paths are in sys.path
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from shared.interfaces.contracts import (
    IPThreatResponse,
    URLThreatResponse,
    AuthCheckResponse,
    UnifiedThreatReport,
)
from threat_intelligence.service import app

client = TestClient(app)

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def print_row(endpoint: str, method: str, status: str, result: bool):
    color = GREEN if result else RED
    symbol = "[PASS]" if result else "[FAIL]"
    print(f"{CYAN}{method:<6}{RESET} | {endpoint:<35} | {color}{status:<15}{RESET} | {color}{symbol}{RESET}")


def run_integration_tests():
    print("=" * 80)
    print(" TraceMail AI -- Master Integration & Contract Verification Test Suite ")
    print(" Threat Intelligence & Integration Verification (SIH26106)           ")
    print("=" * 80)
    print(f"{'Method':<6} | {'Endpoint':<35} | {'Schema Status':<15} | Result")
    print("-" * 80)

    all_passed = True

    # 1. Health Endpoint
    resp = client.get("/health")
    ok = resp.status_code == 200 and resp.json().get("status") == "healthy"
    all_passed = all_passed and ok
    print_row("/health", "GET", f"HTTP {resp.status_code}", ok)

    # 2. IP Threat Contract: GET /api/threat/ip/{ip}
    test_ip = "185.220.101.4"
    resp = client.get(f"/api/threat/ip/{test_ip}")
    ip_ok = False
    if resp.status_code == 200:
        try:
            # Validate through Pydantic Contract
            validated = IPThreatResponse(**resp.json())
            ip_ok = (
                validated.ip == test_ip
                and validated.country == "Germany"
                and validated.abuseScore >= 80
                and validated.malicious is True
            )
        except Exception as e:
            print(f"{RED}[Error parsing IP contract]: {e}{RESET}")
    all_passed = all_passed and ip_ok
    print_row(f"/api/threat/ip/{test_ip}", "GET", "Schema Validated", ip_ok)

    # 3. URL Threat Contract: POST /api/threat/url
    test_url = "http://paypa1-secure.com/login"
    resp = client.post("/api/threat/url", json={"url": test_url})
    url_ok = False
    if resp.status_code == 200:
        try:
            validated = URLThreatResponse(**resp.json())
            url_ok = (
                validated.url == test_url
                and validated.malicious is True
                and validated.category in ("phishing", "malware", "suspicious")
                and validated.vtPositives > 0
            )
        except Exception as e:
            print(f"{RED}[Error parsing URL contract]: {e}{RESET}")
    all_passed = all_passed and url_ok
    print_row("/api/threat/url", "POST", "Schema Validated", url_ok)

    # 4. Email Auth Check Contract: POST /api/threat/auth-check
    headers_payload = {
        "rawHeaders": (
            "From: PayPal Support <support@paypal.com>\r\n"
            "Return-Path: <attacker@paypa1-secure.com>\r\n"
            "Authentication-Results: mx.target.com; spf=fail; dkim=fail; dmarc=fail\r\n"
            "Received: from mail.sketchy-relay.net (185.220.101.4)\r\n"
        )
    }
    resp = client.post("/api/threat/auth-check", json=headers_payload)
    auth_ok = False
    if resp.status_code == 200:
        try:
            validated = AuthCheckResponse(**resp.json())
            auth_ok = (
                validated.spf == "fail"
                and validated.dkim == "fail"
                and validated.dmarc == "fail"
                and "days" in validated.domainAge
                and validated.registrar != "Unknown"
            )
        except Exception as e:
            print(f"{RED}[Error parsing Auth contract]: {e}{RESET}")
    all_passed = all_passed and auth_ok
    print_row("/api/threat/auth-check", "POST", "Schema Validated", auth_ok)

    # 5. Composite Threat JSON Contract (Integration Output Contract)
    comp_resp = client.post(
        "/api/threat/composite",
        json={
            "spf": "fail",
            "dkim": "pass",
            "dmarc": "fail",
            "domainAge": "12 days",
            "registrar": "NameCheap Inc.",
        },
        params={"ip": "185.220.101.4", "url": "http://paypa1-secure.com/login"},
    )
    comp_ok = False
    if comp_resp.status_code == 200:
        try:
            validated = UnifiedThreatReport(**comp_resp.json())
            comp_ok = (
                validated.risk_level in ("HIGH", "CRITICAL")
                and validated.risk_score >= 80
                and validated.malicious_url is True
                and validated.domain_age_days == 12
                and validated.ip_reputation >= 80
            )
        except Exception as e:
            print(f"{RED}[Error parsing Composite report]: {e}{RESET}")
    all_passed = all_passed and comp_ok
    print_row("/api/threat/composite", "POST", "Unified JSON Valid", comp_ok)

    print("-" * 80)
    if all_passed:
        print(f"\n{GREEN}[CONGRATULATIONS] All Master API Contracts passed 100% verification!{RESET}")
        print(f"{GREEN}TraceMail AI Threat Intelligence & Integration Layer is fully operational.{RESET}\n")
        return 0
    else:
        print(f"\n{RED}[FAILURE] Some API contracts failed verification. Inspect output above.{RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_integration_tests())
