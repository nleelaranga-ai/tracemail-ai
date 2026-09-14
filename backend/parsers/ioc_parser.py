"""
TraceMail AI Backend — IOC Extractor Parser
Extracts clean, normalized URLs, domains, IPs, and email addresses.
Enforces system allowlists to prevent self-detection of tracemail.ai and internal infrastructure.
Decodes quoted-printable soft breaks and cleans URL parameters.
"""
import re
import urllib.parse
from typing import Dict, List, Set, Optional
from backend.utils.validators import is_valid_ipv4, is_valid_domain, is_valid_url, is_valid_email


class IOCParser:
    URL_REGEX = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
    IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

    # Domains and platform hosts that must NEVER be extracted as suspect attacker IOCs
    SYSTEM_ALLOWLIST_DOMAINS = {
        "tracemail.ai",
        "railway.app",
        "vercel.app",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "target-corp.com",
    }

    @classmethod
    def is_allowlisted_domain(cls, domain: str, recipient_domain: Optional[str] = None) -> bool:
        """Determines if a domain belongs to internal platform or the recipient organization."""
        if not domain:
            return True
        d = domain.lower().strip()
        if recipient_domain:
            recip = recipient_domain.lower().strip()
            if d == recip or d.endswith("." + recip):
                return True
        for allowed in cls.SYSTEM_ALLOWLIST_DOMAINS:
            if d == allowed or d.endswith("." + allowed):
                return True
        return False

    @classmethod
    def extract_iocs(cls, text: str, recipient_domain: Optional[str] = None) -> Dict[str, List[str]]:
        if not text:
            return {"urls": [], "ips": [], "domains": [], "emails": []}

        # 1. Join MIME quoted-printable soft line breaks (e.g. 'https://example.com/verify=\n')
        clean_text = re.sub(r'=\r?\n', '', text)

        urls: Set[str] = set()
        ips: Set[str] = set()
        domains: Set[str] = set()
        emails: Set[str] = set()

        for match in cls.URL_REGEX.findall(clean_text):
            # Strip trailing punctuation, brackets, quotes, and trailing '=' artifacts
            clean_url = match.rstrip(".,;!?'\"=)>]}\t\r\n")
            clean_url = clean_url.replace("=3D", "=")
            clean_url = clean_url.rstrip("=")

            if is_valid_url(clean_url):
                try:
                    parsed = urllib.parse.urlparse(clean_url)
                    host = parsed.netloc.split(":")[0].lower().strip()
                    if is_valid_domain(host):
                        if not cls.is_allowlisted_domain(host, recipient_domain):
                            domains.add(host)
                    urls.add(clean_url)
                except Exception:
                    pass

        for match in cls.IP_REGEX.findall(clean_text):
            if is_valid_ipv4(match):
                # Omit loopback and broadcast
                if match not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                    ips.add(match)

        for match in cls.EMAIL_REGEX.findall(clean_text):
            if is_valid_email(match):
                emails.add(match)
                try:
                    domain_part = match.split("@")[1].lower().strip()
                    if is_valid_domain(domain_part):
                        if not cls.is_allowlisted_domain(domain_part, recipient_domain):
                            domains.add(domain_part)
                except Exception:
                    pass

        return {
            "urls": sorted(list(urls)),
            "ips": sorted(list(ips)),
            "domains": sorted(list(domains)),
            "emails": sorted(list(emails))
        }
