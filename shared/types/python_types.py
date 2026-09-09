"""
TraceMail AI — Shared Python Type Aliases & TypedDicts
"""

from typing import Dict, Any, List, TypedDict, Optional, Union

# Common type aliases
JSONDict = Dict[str, Any]
IPList = List[str]
URLList = List[str]
DomainList = List[str]


class ExtractedIOCDict(TypedDict, total=False):
    ips: List[str]
    urls: List[str]
    domains: List[str]
    emails: List[str]
    hashes: List[str]
    sender_claim: Optional[str]
    sender_actual: Optional[str]


class ThreatScoreFactors(TypedDict, total=False):
    spf_score: int
    dkim_score: int
    dmarc_score: int
    ip_abuse_score: int
    vt_score: int
    domain_age_score: int
    url_heuristic_score: int
