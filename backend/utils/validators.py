"""
TraceMail AI Backend — Input Validation Utilities
"""
import re
import ipaddress
from typing import Optional

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def is_valid_ipv4(ip: str) -> bool:
    try:
        ip_obj = ipaddress.IPv4Address(ip.strip())
        return not ip_obj.is_private and not ip_obj.is_loopback
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain.strip()))


def is_valid_url(url: str) -> bool:
    if not url:
        return False
    return bool(URL_REGEX.match(url.strip()))


def is_valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def is_valid_hash(h: str) -> bool:
    if not h:
        return False
    h = h.strip()
    return bool(MD5_REGEX.match(h) or SHA256_REGEX.match(h))
