"""
TraceMail AI — Shared Validation Engine
Robust validators for cybersecurity artifacts: IPs, domains, URLs, emails, and hashes.
"""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# RFC 5322 Compliant Email Regex
EMAIL_REGEX = re.compile(
    r"(?i)^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
)

# RFC 1035 Domain Regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Hash Regexes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def is_valid_ip(ip_str: str) -> bool:
    """Check if the provided string is a syntactically valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """
    Check if the IP is globally routable (not private RFC 1918, loopback, link-local, or reserved).
    """
    if not is_valid_ip(ip_str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_global
    except ValueError:
        return False


def is_valid_domain(domain_str: str) -> bool:
    """Check if the domain conforms to standard DNS hostname rules."""
    if not domain_str or not isinstance(domain_str, str):
        return False
    domain = domain_str.strip().lower()
    if len(domain) > 253 or "." not in domain:
        return False
    return bool(DOMAIN_REGEX.match(domain))


def is_valid_url(url_str: str) -> bool:
    """Check if the string is a valid HTTP/HTTPS URL with host."""
    if not url_str or not isinstance(url_str, str):
        return False
    try:
        parsed = urlparse(url_str.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def is_valid_email(email_str: str) -> bool:
    """Check if the string matches an RFC-compliant email address."""
    if not email_str or not isinstance(email_str, str):
        return False
    return bool(EMAIL_REGEX.match(email_str.strip()))


def extract_email_domain(email_str: str) -> Optional[str]:
    """Extract and normalize the domain part of an email address."""
    if not is_valid_email(email_str):
        return None
    return email_str.strip().split("@")[-1].lower()


def is_valid_hash(hash_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate if string is MD5, SHA1, or SHA256.
    Returns: (is_valid, hash_type)
    """
    if not hash_str or not isinstance(hash_str, str):
        return False, None
    h = hash_str.strip()
    if MD5_REGEX.match(h):
        return True, "md5"
    if SHA1_REGEX.match(h):
        return True, "sha1"
    if SHA256_REGEX.match(h):
        return True, "sha256"
    return False, None
