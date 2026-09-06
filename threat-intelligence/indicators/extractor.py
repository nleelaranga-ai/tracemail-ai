"""
TraceMail AI — Indicator of Compromise (IOC) Extractor
High-precision regex and defanging parser extracting IPs, URLs, domains, emails, and file hashes.
"""

import re
from typing import Dict, List, Set, Tuple, Optional, Any
from urllib.parse import urlparse
from shared.validation.validators import (
    is_valid_ip,
    is_public_ip,
    is_valid_domain,
    is_valid_url,
    is_valid_email,
    is_valid_hash,
)

# Regex Patterns for IOC extraction
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
URL_REGEX = re.compile(
    r"(?i)\b(?:https?|hxxps?|ftp)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"
)
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def defang_url(url: str) -> str:
    """Safely neutralize a URL for storage/display."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def refang_url(url: str) -> str:
    """Restore a defanged URL for scanning."""
    return (
        url.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("[dot]", ".")
    )


class IOCExtractor:
    """Extracts cybersecurity indicators from raw email headers, body text, or attachments."""

    def __init__(self):
        pass

    def extract_all(self, text: str) -> Dict[str, Any]:
        """
        Extract structured IOC collection.
        Returns: { ips: list, public_ips: list, urls: list, domains: list, emails: list, hashes: list }
        """
        if not text or not isinstance(text, str):
            return {
                "ips": [],
                "public_ips": [],
                "urls": [],
                "domains": [],
                "emails": [],
                "hashes": [],
            }

        normalized_text = refang_url(text)

        # 1. Extract IPs
        raw_ips = IPV4_REGEX.findall(normalized_text)
        valid_ips: Set[str] = set()
        public_ips: Set[str] = set()
        for ip in raw_ips:
            if is_valid_ip(ip):
                valid_ips.add(ip)
                if is_public_ip(ip):
                    public_ips.add(ip)

        # 2. Extract URLs
        raw_urls = URL_REGEX.findall(normalized_text)
        valid_urls: Set[str] = set()
        extracted_domains: Set[str] = set()

        for u in raw_urls:
            cleaned_u = u.rstrip(".,;)>\"'")
            if is_valid_url(cleaned_u):
                valid_urls.add(cleaned_u)
                parsed = urlparse(cleaned_u)
                if parsed.netloc:
                    domain = parsed.netloc.split(":")[0].lower()
                    if is_valid_domain(domain):
                        extracted_domains.add(domain)

        # 3. Extract Emails
        raw_emails = EMAIL_REGEX.findall(normalized_text)
        valid_emails: Set[str] = set()
        for em in raw_emails:
            cleaned_em = em.rstrip(".,;)>\"'").lower()
            if is_valid_email(cleaned_em):
                valid_emails.add(cleaned_em)
                domain = cleaned_em.split("@")[-1]
                if is_valid_domain(domain):
                    extracted_domains.add(domain)

        # 4. Extract Hashes
        raw_hashes = HASH_REGEX.findall(normalized_text)
        valid_hashes: Set[str] = set()
        for h in raw_hashes:
            is_valid, _ = is_valid_hash(h)
            if is_valid:
                valid_hashes.add(h.lower())

        return {
            "ips": sorted(list(valid_ips)),
            "public_ips": sorted(list(public_ips)),
            "urls": sorted(list(valid_urls)),
            "domains": sorted(list(extracted_domains)),
            "emails": sorted(list(valid_emails)),
            "hashes": sorted(list(valid_hashes)),
        }

    def extract_sender_identity(self, headers_text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract (senderClaim, senderActual) by contrasting From and Return-Path / Received.
        """
        claim_match = re.search(r"(?i)^From:\s*(.+)$", headers_text, re.MULTILINE)
        sender_claim = claim_match.group(1).strip() if claim_match else None

        actual_match = re.search(r"(?i)^Return-Path:\s*<?([^>\r\n]+)>?", headers_text, re.MULTILINE)
        sender_actual = actual_match.group(1).strip() if actual_match else None

        # If Return-Path absent, look for sender relay identity
        if not sender_actual:
            received_match = re.search(r"(?i)Received:\s*from\s+([^\s]+)", headers_text)
            if received_match:
                sender_actual = received_match.group(1).strip()

        return sender_claim, sender_actual


ioc_extractor = IOCExtractor()
