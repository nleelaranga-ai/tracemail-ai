"""
TraceMail AI Backend — IOC Extractor Parser
"""
import re
from typing import Dict, List, Set
from backend.utils.validators import is_valid_ipv4, is_valid_domain, is_valid_url, is_valid_email


class IOCParser:
    URL_REGEX = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
    IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

    @classmethod
    def extract_iocs(cls, text: str) -> Dict[str, List[str]]:
        if not text:
            return {"urls": [], "ips": [], "domains": [], "emails": []}

        urls: Set[str] = set()
        ips: Set[str] = set()
        domains: Set[str] = set()
        emails: Set[str] = set()

        for match in cls.URL_REGEX.findall(text):
            clean_url = match.rstrip(".,;!?'\"")
            if is_valid_url(clean_url):
                urls.add(clean_url)
                # extract domain from URL
                domain_part = clean_url.split("://")[1].split("/")[0].split(":")[0]
                if is_valid_domain(domain_part):
                    domains.add(domain_part)

        for match in cls.IP_REGEX.findall(text):
            if is_valid_ipv4(match):
                ips.add(match)

        for match in cls.EMAIL_REGEX.findall(text):
            if is_valid_email(match):
                emails.add(match)
                domain_part = match.split("@")[1]
                if is_valid_domain(domain_part):
                    domains.add(domain_part)

        return {
            "urls": sorted(list(urls)),
            "ips": sorted(list(ips)),
            "domains": sorted(list(domains)),
            "emails": sorted(list(emails))
        }
