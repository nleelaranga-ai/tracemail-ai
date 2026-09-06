"""
TraceMail AI — Database & Fixture Seeder
Generates realistic sample phishing and legitimate RFC 822 email scenarios for development, testing, and SIH demos.
"""

import os
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_CASES = [
    {
        "filename": "01_paypal_credential_phish.eml",
        "title": "High-Risk PayPal Impersonation / Credential Harvester",
        "sender_claim": "PayPal Security <service@paypal.com>",
        "sender_actual": "attacker@sketchy-relay.net",
        "subject": "Urgent: Your PayPal account has been suspended",
        "origin_ip": "185.220.101.4",
        "country": "Germany",
        "city": "Frankfurt",
        "target_url": "http://paypa1-secure.com/login",
        "risk_level": "HIGH",
        "risk_score": 94,
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "raw_headers": (
            "From: PayPal Security <service@paypal.com>\r\n"
            "To: victim@target-corp.com\r\n"
            "Subject: Urgent: Your PayPal account has been suspended\r\n"
            "Date: Sun, 06 Sep 2026 09:58:12 +0200\r\n"
            "Return-Path: <attacker@sketchy-relay.net>\r\n"
            "Authentication-Results: mx.target-corp.com; spf=fail (sender IP is 185.220.101.4); dkim=fail; dmarc=fail\r\n"
            "Received: from mail.sketchy-relay.net ([185.220.101.4]) by mx.target-corp.com with ESMTP id p43k89;\r\n"
            "Received: from unknown (HELO internal-vpn.net) ([192.168.1.105]) by mail.sketchy-relay.net;\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
        ),
        "body": (
            "Dear Customer,\n\n"
            "We detected unauthorized login attempts to your PayPal account from Frankfurt, Germany.\n"
            "To protect your financial security, your account access has been restricted.\n\n"
            "Please verify your credentials immediately within 24 hours:\n"
            "http://paypa1-secure.com/login\n\n"
            "Failure to verify will result in permanent account termination.\n\n"
            "PayPal Risk Management Operations\n"
        ),
    },
    {
        "filename": "02_ceo_fraud_bec.eml",
        "title": "Business Email Compromise (BEC) Wire Transfer",
        "sender_claim": "Jonathan Vance, CEO <ceo@company-execs.net>",
        "sender_actual": "wire-ops@offshore-desk.com",
        "subject": "CONFIDENTIAL: Urgent Acquisition Wire Needed",
        "origin_ip": "194.26.29.112",
        "country": "Russia",
        "city": "Moscow",
        "target_url": "https://secure-document-vault.top/invoice-8902",
        "risk_level": "HIGH",
        "risk_score": 88,
        "spf": "fail",
        "dkim": "none",
        "dmarc": "fail",
        "raw_headers": (
            "From: Jonathan Vance, CEO <ceo@company-execs.net>\r\n"
            "To: finance-director@target-corp.com\r\n"
            "Subject: CONFIDENTIAL: Urgent Acquisition Wire Needed\r\n"
            "Date: Sun, 06 Sep 2026 08:30:00 +0300\r\n"
            "Return-Path: <wire-ops@offshore-desk.com>\r\n"
            "Authentication-Results: mx.target-corp.com; spf=fail; dkim=none; dmarc=fail\r\n"
            "Received: from mail.hostpalace-relay.ru ([194.26.29.112]) by mx.target-corp.com;\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
        ),
        "body": (
            "Hi Michael,\n\n"
            "I am currently in closed negotiations for our strategic supplier acquisition.\n"
            "We need an initial escrow disbursement of $142,500 executed before banking cut-off.\n"
            "Please review the escrow instructions here: https://secure-document-vault.top/invoice-8902\n"
            "Do not call my cell as I am in meetings; confirm via this email once processed.\n\n"
            "Best,\nJonathan Vance\n"
        ),
    },
    {
        "filename": "03_malware_invoice.eml",
        "title": "Trojan Downloader / Malicious PDF Link",
        "sender_claim": "Billing Department <billing@quickbooks-accounting.org>",
        "sender_actual": "spammer@bulletproof-vps.com",
        "subject": "Overdue Invoice INV-2026-9011 - Immediate Attention Required",
        "origin_ip": "45.154.255.89",
        "country": "Netherlands",
        "city": "Amsterdam",
        "target_url": "http://billing-update-check.xyz/download.php?id=9011",
        "risk_level": "CRITICAL",
        "risk_score": 96,
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "raw_headers": (
            "From: Billing Department <billing@quickbooks-accounting.org>\r\n"
            "To: accounts@target-corp.com\r\n"
            "Subject: Overdue Invoice INV-2026-9011 - Immediate Attention Required\r\n"
            "Date: Sun, 06 Sep 2026 07:15:20 +0100\r\n"
            "Return-Path: <spammer@bulletproof-vps.com>\r\n"
            "Authentication-Results: mx.target-corp.com; spf=fail; dkim=fail; dmarc=fail\r\n"
            "Received: from nl-relay-89.vps.net ([45.154.255.89]) by mx.target-corp.com;\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
        ),
        "body": (
            "Your remittance for invoice #INV-2026-9011 has failed.\n"
            "Download your updated ledger and dispute form: http://billing-update-check.xyz/download.php?id=9011\n"
            "Sha256 checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        ),
    },
    {
        "filename": "04_legitimate_github_security.eml",
        "title": "Legitimate GitHub Security Alert (Safe Baseline)",
        "sender_claim": "GitHub <noreply@github.com>",
        "sender_actual": "noreply@github.com",
        "subject": "[GitHub] A personal access token was created",
        "origin_ip": "142.250.1.27",
        "country": "United States",
        "city": "Mountain View",
        "target_url": "https://github.com/settings/tokens",
        "risk_level": "SAFE",
        "risk_score": 5,
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "raw_headers": (
            "From: GitHub <noreply@github.com>\r\n"
            "To: developer@target-corp.com\r\n"
            "Subject: [GitHub] A personal access token was created\r\n"
            "Date: Sun, 06 Sep 2026 10:00:00 +0000\r\n"
            "Return-Path: <noreply@github.com>\r\n"
            "Authentication-Results: mx.target-corp.com; spf=pass; dkim=pass; dmarc=pass\r\n"
            "Received: from smtp.github.com ([142.250.1.27]) by mx.target-corp.com;\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=github.com; s=s20210201;\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
        ),
        "body": (
            "Hey developer,\n\n"
            "A personal access token (classic) was recently created for your account.\n"
            "If you generated this token, no further action is needed.\n"
            "Review your security settings: https://github.com/settings/tokens\n\n"
            "Thanks,\nThe GitHub Team\n"
        ),
    },
    {
        "filename": "05_multi_hop_spoofed_relay.eml",
        "title": "Multi-Hop Spoofed Relay Transmission",
        "sender_claim": "IT Support <admin@corporate-auth.com>",
        "sender_actual": "relay-node@tor-exit.de",
        "subject": "Mandatory Password Reset Required",
        "origin_ip": "185.220.101.4",
        "country": "Germany",
        "city": "Frankfurt",
        "target_url": "http://corporate-auth.top/reset-password",
        "risk_level": "HIGH",
        "risk_score": 91,
        "spf": "softfail",
        "dkim": "none",
        "dmarc": "fail",
        "raw_headers": (
            "From: IT Support <admin@corporate-auth.com>\r\n"
            "To: employee@target-corp.com\r\n"
            "Subject: Mandatory Password Reset Required\r\n"
            "Date: Sun, 06 Sep 2026 11:20:00 +0200\r\n"
            "Return-Path: <relay-node@tor-exit.de>\r\n"
            "Authentication-Results: mx.target-corp.com; spf=softfail; dkim=none; dmarc=fail\r\n"
            "Received: from mx.target-corp.com by internal-mail.target-corp.com;\r\n"
            "Received: from mail.tor-exit.de ([185.220.101.4]) by mx.target-corp.com;\r\n"
            "Received: from proxy-node.lan ([10.0.0.45]) by mail.tor-exit.de;\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
        ),
        "body": (
            "Attention Employee:\n\n"
            "Your Active Directory credentials expire in 2 hours.\n"
            "Navigate to the single-sign-on portal to sync your key:\n"
            "http://corporate-auth.top/reset-password\n"
        ),
    },
]


def seed_all():
    print("=" * 60)
    print(" TraceMail AI — Seeding Sample Phishing & Legitimate Cases ")
    print("=" * 60)

    for case in SAMPLE_CASES:
        file_path = FIXTURES_DIR / case["filename"]
        eml_content = f"{case['raw_headers']}\r\n{case['body']}"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(eml_content)
        print(f"[+] Written EML Fixture: {file_path.name}")

    # Also save manifest JSON for programmatic ingestion
    manifest_path = FIXTURES_DIR / "sample_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(SAMPLE_CASES, f, indent=2)
    print(f"[OK] Manifest created: {manifest_path.name}")
    print(f"[SUCCESS] 5 Test Cases Seeded in {FIXTURES_DIR}")


if __name__ == "__main__":
    seed_all()
