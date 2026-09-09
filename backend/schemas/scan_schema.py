"""
TraceMail AI Backend — Scan Schemas
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class ScanEmailRequest(BaseModel):
    emailBody: str = Field(..., description="Plain-text body of the email")
    headers: str = Field(..., description="Raw email headers block")


class ScanUrlRequest(BaseModel):
    url: str = Field(..., description="URL to scan for phishing/malware")


class ScanDomainRequest(BaseModel):
    domain: str = Field(..., description="Domain name to check reputation")


class ScanResultResponse(BaseModel):
    indicator: str
    type: str
    reputation_score: int
    verdict: str
    is_malicious: bool
    details: Dict[str, Any] = {}
