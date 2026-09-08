"""
TraceMail AI — Master API Contracts & Pydantic Schemas
Defines the single source of truth for all module request/response data contracts.
Complies with Section 6 of the Master Architecture and Integration Contracts.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from shared.enums import RiskLevel, ThreatType, AuthVerdict, InvestigationStatus


# ==============================================================================
# PHASE 1 & MASTER API CONTRACT — THREAT INTELLIGENCE
# ==============================================================================

class IPThreatResponse(BaseModel):
    """
    Contract for: GET /api/threat/ip/{ip}
    Consumed by: Backend Team, Maps & Attack Graph Team
    """
    ip: str = Field(..., description="Target IPv4 or IPv6 address")
    country: str = Field("Unknown", description="Country name of origin")
    city: str = Field("Unknown", description="City of origin")
    lat: float = Field(0.0, description="Latitude coordinate")
    lon: float = Field(0.0, description="Longitude coordinate")
    isp: str = Field("Unknown", description="Internet Service Provider")
    asn: str = Field("Unknown", description="Autonomous System Number")
    abuseScore: int = Field(0, ge=0, le=100, description="Confidence of abuse score from AbuseIPDB (0-100)")
    malicious: bool = Field(False, description="Flag indicating malicious reputation")

    model_config = {
        "json_schema_extra": {
            "example": {
                "ip": "185.220.101.4",
                "country": "Germany",
                "city": "Frankfurt",
                "lat": 50.1109,
                "lon": 8.6821,
                "isp": "M247 Ltd",
                "asn": "AS9009",
                "abuseScore": 92,
                "malicious": True
            }
        }
    }


class URLThreatRequest(BaseModel):
    """
    Contract for: POST /api/threat/url (Request)
    """
    url: str = Field(..., description="Full URL to analyze")


class URLThreatResponse(BaseModel):
    """
    Contract for: POST /api/threat/url (Response)
    Consumed by: Backend, AI Engine, Reports
    """
    url: str = Field(..., description="Analyzed URL")
    malicious: bool = Field(False, description="Whether URL was flagged by scanners")
    category: str = Field("clean", description="Detected category: phishing, malware, or clean")
    scanDate: str = Field(..., description="ISO 8601 scan timestamp")
    vtPositives: int = Field(0, description="Number of security vendors flagging as malicious")
    vtTotal: int = Field(0, description="Total security vendors evaluated")

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "http://paypa1-secure.com/login",
                "malicious": True,
                "category": "phishing",
                "scanDate": "2026-09-06T10:00:00Z",
                "vtPositives": 14,
                "vtTotal": 90
            }
        }
    }


class AuthCheckRequest(BaseModel):
    """
    Contract for: POST /api/threat/auth-check (Request)
    """
    rawHeaders: str = Field(..., description="Raw RFC 822 / MIME email headers string")


class AuthCheckResponse(BaseModel):
    """
    Contract for: POST /api/threat/auth-check (Response)
    Consumed by: Backend, Reports
    """
    spf: str = Field("none", description="SPF validation status: pass | fail | none | softfail")
    dkim: str = Field("none", description="DKIM signature validation status: pass | fail | none")
    dmarc: str = Field("none", description="DMARC alignment status: pass | fail | none")
    domainAge: str = Field("Unknown", description="Domain age human string, e.g. '14 days'")
    registrar: str = Field("Unknown", description="Domain registrar name from WHOIS")

    model_config = {
        "json_schema_extra": {
            "example": {
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "domainAge": "14 days",
                "registrar": "NameCheap Inc."
            }
        }
    }


class UnifiedThreatReport(BaseModel):
    """
    Composite Threat JSON Contract (Integration Output Contract).
    Consumed directly by Backend Team and fed to AI, Maps, Reports.
    """
    risk_level: str = Field("SAFE", description="Overall risk rating: SAFE, SUSPICIOUS, HIGH, CRITICAL")
    risk_score: int = Field(0, ge=0, le=100, description="Normalized composite threat score (0-100)")
    malicious_url: bool = Field(False, description="Whether any URL extracted from the email is malicious")
    domain_age_days: int = Field(0, description="Domain age in days (< 30 days is high risk)")
    ip_reputation: int = Field(0, ge=0, le=100, description="Maximum abuse score observed in IP hops")
    country: str = Field("Unknown", description="Originating relay country")
    spf: str = Field("none", description="SPF result: PASS, FAIL, NONE, SOFTFAIL")
    dkim: str = Field("none", description="DKIM result: PASS, FAIL, NONE")
    dmarc: str = Field("none", description="DMARC result: PASS, FAIL, NONE")

    model_config = {
        "json_schema_extra": {
            "example": {
                "risk_level": "HIGH",
                "risk_score": 94,
                "malicious_url": True,
                "domain_age_days": 12,
                "ip_reputation": 98,
                "country": "Germany",
                "spf": "FAIL",
                "dkim": "PASS",
                "dmarc": "FAIL"
            }
        }
    }


# ==============================================================================
# DOWNSTREAM MODULE CONTRACTS (For Full Integration Verification)
# ==============================================================================

class AIEntities(BaseModel):
    """Extracted IOC entities from AI engine."""
    urls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    senderClaim: Optional[str] = None
    senderActual: Optional[str] = None


class AIPhishingRequest(BaseModel):
    """POST /api/ai/phishing-score request."""
    emailBody: str
    headers: str


class AIPhishingResponse(BaseModel):
    """POST /api/ai/phishing-score response."""
    phishingScore: int = Field(..., ge=0, le=100)
    verdict: str = Field(..., description="phishing | suspicious | safe")
    explanation: str
    entities: AIEntities


class GeoJSONGeometry(BaseModel):
    type: str
    coordinates: Any


class GeoJSONFeature(BaseModel):
    type: str = "Feature"
    geometry: GeoJSONGeometry
    properties: Dict[str, Any]


class GeoJSONFeatureCollection(BaseModel):
    type: str = "FeatureCollection"
    features: List[GeoJSONFeature]


class TimelineEvent(BaseModel):
    step: int
    server: str
    ip: str
    timestamp: str
    malicious: bool = False


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # sender, relay, recipient
    malicious: Optional[bool] = False


class GraphEdge(BaseModel):
    from_node: str = Field(..., alias="from")
    to_node: str = Field(..., alias="to")

    model_config = {"populate_by_name": True}


class AttackGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class InvestigationDetailResponse(BaseModel):
    """GET /api/investigations/{id} response consumed by Frontend."""
    id: str
    status: InvestigationStatus
    sender: str
    subject: str
    receivedAt: str
    aiResult: Optional[AIPhishingResponse] = None
    threatResults: List[Dict[str, Any]] = Field(default_factory=list)
    mapUrl: Optional[str] = None
    timelineUrl: Optional[str] = None
    graphUrl: Optional[str] = None
    reportUrl: Optional[str] = None


# ==============================================================================
# REAL-TIME UNIFIED INVESTIGATION CONTRACT (SIH 2026 Target Architecture)
# ==============================================================================

class InvestigationTimelineStep(BaseModel):
    time: str
    event: str


class IOCItem(BaseModel):
    type: str  # "url" | "ip" | "domain" | "hash" | "attachment"
    value: str
    category: str = "General"
    severity: str = "medium"  # "low" | "medium" | "high" | "critical"


class VirusTotalSummary(BaseModel):
    malicious_vendors: int = 0
    total_vendors: int = 0
    scan_date: str = ""
    positives: int = 0


class AbuseIPDBSummary(BaseModel):
    confidence_score: int = 0
    isp: str = "Unknown"
    total_reports: int = 0
    is_malicious: bool = False


class WHOISSummary(BaseModel):
    registrar: str = "Unknown"
    created_date: str = "Unknown"
    expiry_date: str = "Unknown"
    domain_age: str = "Unknown"
    domain_age_days: int = 0


class DNSSummary(BaseModel):
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


class URLScanSummary(BaseModel):
    verdict: str = "clean"
    score: int = 0
    page_title: str = ""
    screenshot_url: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)


class AIAnalysisSummary(BaseModel):
    prediction: str = "Suspicious"
    confidence: float = 0.0
    summary: str = ""
    reasons: List[str] = Field(default_factory=list)


class UnifiedInvestigationResponse(BaseModel):
    """
    Master unified investigation response shared across all modules.
    Fulfills Target Architecture Contract Section 7.
    """
    scan_id: str
    sender: str
    domain: str
    ip: str
    country: str
    city: str
    latitude: float
    longitude: float
    threat_score: int = Field(..., ge=0, le=100)
    risk_level: str  # "Low" | "Medium" | "High" | "Critical"
    ai_summary: str
    timeline: List[InvestigationTimelineStep] = Field(default_factory=list)
    virus_total: VirusTotalSummary = Field(default_factory=VirusTotalSummary)
    abuse_ipdb: AbuseIPDBSummary = Field(default_factory=AbuseIPDBSummary)
    whois: WHOISSummary = Field(default_factory=WHOISSummary)
    dns: DNSSummary = Field(default_factory=DNSSummary)
    urlscan: URLScanSummary = Field(default_factory=URLScanSummary)
    ai_analysis: AIAnalysisSummary = Field(default_factory=AIAnalysisSummary)
    ioc: List[IOCItem] = Field(default_factory=list)

    # Backwards-compatibility aliases for existing frontend and test suites
    id: Optional[str] = None
    investigationId: Optional[str] = None
    status: str = "complete"
    recipient: Optional[str] = None
    subject: Optional[str] = None
    receivedAt: Optional[str] = None
    phishingScore: Optional[int] = None
    verdict: Optional[str] = None
    explanation: Optional[str] = None
    aiResult: Optional[Any] = None
    threatResults: List[Dict[str, Any]] = Field(default_factory=list)
    mapUrl: Optional[str] = None
    timelineUrl: Optional[str] = None
    graphUrl: Optional[str] = None
    reportUrl: Optional[str] = None
    geojson_map: Optional[Dict[str, Any]] = None
    attack_graph: Optional[Dict[str, Any]] = None

