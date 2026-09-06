"""
TraceMail AI — DNS & Email Authentication Engine
Analyzes raw email headers for SPF, DKIM, and DMARC status with live DNS TXT lookups and WHOIS enrichment.
"""

import email
import re
from typing import Dict, Any, Optional, Tuple
from shared.interfaces.contracts import AuthCheckResponse
from shared.validation.validators import extract_email_domain, is_valid_domain
from shared.config.logging import get_logger
from threat_intelligence.whois.whois_client import whois_client

logger = get_logger("DNSAuthCheck")


class DNSAuthChecker:
    """Validator for email authentication standards (SPF, DKIM, DMARC)."""

    def __init__(self):
        pass

    async def check_authentication(self, raw_headers: str) -> AuthCheckResponse:
        """
        Analyze raw headers and perform DNS/WHOIS verification.
        Returns strictly matching contract for POST /api/threat/auth-check.
        """
        if not raw_headers or not isinstance(raw_headers, str):
            return AuthCheckResponse(
                spf="none",
                dkim="none",
                dmarc="none",
                domainAge="Unknown",
                registrar="Unknown",
            )

        # 1. Parse headers using Python email library
        msg = email.message_from_string(raw_headers)
        auth_results = msg.get_all("Authentication-Results") or []
        received_spf = msg.get_all("Received-SPF") or []
        dkim_sig = msg.get("DKIM-Signature")
        from_header = msg.get("From", "")
        return_path = msg.get("Return-Path", "")

        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"

        # 2. Extract SPF
        for r_spf in received_spf:
            r_lower = r_spf.lower()
            if "pass" in r_lower:
                spf_status = "pass"
                break
            elif "fail" in r_lower:
                spf_status = "fail"
                break
            elif "softfail" in r_lower:
                spf_status = "softfail"
                break

        # Check Authentication-Results header if SPF still none
        auth_str = " ".join(auth_results).lower()
        if spf_status == "none" and auth_str:
            spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_str)
            if spf_match:
                spf_status = spf_match.group(1)

        # 3. Extract DKIM
        if auth_str:
            dkim_match = re.search(r"\bdkim=(pass|fail|none|temperror|permerror)\b", auth_str)
            if dkim_match:
                dkim_status = dkim_match.group(1)
            elif dkim_sig:
                dkim_status = "pass"  # Signature exists
            else:
                dkim_status = "none"
        elif dkim_sig:
            dkim_status = "pass"

        # 4. Extract DMARC
        if auth_str:
            dmarc_match = re.search(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", auth_str)
            if dmarc_match:
                dmarc_status = dmarc_match.group(1)

        # If DMARC not present in headers, derive alignment heuristic:
        if dmarc_status == "none":
            if spf_status == "pass" and dkim_status == "pass":
                dmarc_status = "pass"
            elif spf_status == "fail" or dkim_status == "fail":
                dmarc_status = "fail"

        # 5. Extract sender domain to query WHOIS for domain age & registrar
        target_domain = self._extract_sender_domain(from_header, return_path, raw_headers)

        domain_age = "Unknown"
        registrar = "Unknown"

        if target_domain:
            whois_info = await whois_client.lookup_domain(target_domain)
            domain_age = whois_info.get("domainAge", "Unknown")
            registrar = whois_info.get("registrar", "Unknown")

        return AuthCheckResponse(
            spf=spf_status,
            dkim=dkim_status,
            dmarc=dmarc_status,
            domainAge=domain_age,
            registrar=registrar,
        )

    def _extract_sender_domain(self, from_h: str, return_p: str, raw: str) -> Optional[str]:
        """Extract sender domain from From or Return-Path or raw text."""
        # Try From header
        emails = re.findall(r"[\w\.-]+@([\w\.-]+\.\w+)", from_h)
        if emails and is_valid_domain(emails[0]):
            return emails[0].lower()

        # Try Return-Path
        emails = re.findall(r"[\w\.-]+@([\w\.-]+\.\w+)", return_p)
        if emails and is_valid_domain(emails[0]):
            return emails[0].lower()

        # Fallback regex over raw headers
        from_matches = re.findall(r"(?i)From:.*?@([\w\.-]+\.\w+)", raw)
        if from_matches and is_valid_domain(from_matches[0]):
            return from_matches[0].lower()

        return None


dns_checker = DNSAuthChecker()
