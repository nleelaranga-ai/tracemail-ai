"""
TraceMail AI Backend — Report & Investigation Schemas (Section 6 & 9.1 Compliance)
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class ExtractedEntities(BaseModel):
    urls: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    senderClaim: Optional[str] = None
    senderActual: Optional[str] = None


class AIResult(BaseModel):
    phishingScore: int = Field(..., ge=0, le=100)
    verdict: str = Field(..., description="'phishing' | 'suspicious' | 'safe'")
    explanation: str
    entities: ExtractedEntities


class ThreatItem(BaseModel):
    type: str = Field(..., description="'ip' | 'url' | 'domain'")
    value: str
    reputation: int = Field(..., ge=0, le=100)
    geo: Optional[str] = None
    malicious: bool = False


class InvestigationDetailResponse(BaseModel):
    id: str
    status: str = "complete"
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    receivedAt: str
    aiResult: Optional[AIResult] = None
    threatResults: List[ThreatItem] = []
    mapUrl: str
    timelineUrl: str
    graphUrl: str
    reportUrl: str
    threat_score: Optional[int] = None
    threatScore: Optional[int] = None
    risk_level: Optional[str] = None
    riskLevel: Optional[str] = None
    origin_ip: Optional[str] = None
    origin_city: Optional[str] = None
    origin_country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    threat_intel: Optional[Dict[str, Any]] = None
    threatIntel: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[Dict[str, Any]] = None
    aiAnalysis: Optional[Dict[str, Any]] = None
    timeline: Optional[List[Dict[str, Any]]] = None
    iocs: Optional[List[Dict[str, Any]]] = None
    entities: Optional[Any] = None
    auth_results: Optional[Dict[str, Any]] = None
    authResults: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class InvestigationSummary(BaseModel):
    id: str
    status: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    receivedAt: str
    verdict: str
    phishingScore: int


class TimelineStep(BaseModel):
    step: int
    server: str
    ip: str
    timestamp: str
    malicious: bool = False


class AttackGraphNode(BaseModel):
    id: str
    label: str
    type: str  # sender, relay, recipient
    malicious: bool = False


class AttackGraphEdge(BaseModel):
    from_: str = Field(..., alias="from")
    to: str

    class Config:
        populate_by_name = True


class AttackGraph(BaseModel):
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []
