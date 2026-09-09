"""
TraceMail AI — Team Reports: Reports Engine
File   : team_reports/reports/json/json_report.py
Purpose: Produces machine-readable JSON forensic reports from assembled
         investigation data received from the Backend API.

Integration:
    Backend → POST /api/v1/reports/generate
              GET  /api/report/json/{investigationId}
    The reports engine never queries the DB directly.
    All data arrives pre-assembled as a validated InvestigationPayload.

Output contract: Conforms to schemas/report_schema.json (JSON Schema Draft-07)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class VerdictEnum(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class AuthResultEnum(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class ThreatTypeEnum(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SPOOFING = "spoofing"
    BEC = "business_email_compromise"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Sub-models (match backend API contract exactly)
# ---------------------------------------------------------------------------


class CaseSummary(BaseModel):
    """High-level summary of the investigation case."""

    investigation_id: str = Field(..., description="Unique investigation identifier")
    subject: str = Field(..., description="Email subject line")
    from_address: str = Field(..., description="Sender email address")
    to_addresses: list[str] = Field(..., description="List of recipient addresses")
    received_at: datetime = Field(..., description="Email received timestamp (UTC)")
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Analysis completion timestamp (UTC)",
    )
    threat_type: ThreatTypeEnum = Field(
        default=ThreatTypeEnum.UNKNOWN, description="Primary detected threat type"
    )
    analyst_notes: str | None = Field(default=None, description="Optional analyst notes")


class RiskScore(BaseModel):
    """Composite risk scoring from all detection engines."""

    overall_score: float = Field(..., ge=0.0, le=100.0, description="Overall risk score 0-100")
    verdict: VerdictEnum = Field(..., description="Final threat verdict")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence 0.0-1.0")
    phishing_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Phishing engine score"
    )
    spoofing_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Spoofing detection score"
    )
    malware_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Malware probability score"
    )
    bec_score: float = Field(default=0.0, ge=0.0, le=100.0, description="BEC detection score")

    @field_validator("overall_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        return round(v, 2)


class SenderAnalysis(BaseModel):
    """Detailed sender identity and infrastructure analysis."""

    display_name: str = Field(..., description="Display name shown in email client")
    email_address: str = Field(..., description="Actual From: header address")
    reply_to: str | None = Field(default=None, description="Reply-To address if different")
    return_path: str | None = Field(default=None, description="Return-Path header")
    sender_domain: str = Field(..., description="Sending domain")
    originating_ip: str | None = Field(default=None, description="First hop IP address")
    mail_server: str | None = Field(default=None, description="Identified mail server")
    domain_age_days: int | None = Field(
        default=None, description="Domain age in days (None = unknown)"
    )
    domain_registered: str | None = Field(
        default=None, description="Domain registration date ISO 8601"
    )
    is_free_email: bool = Field(
        default=False, description="Whether sender uses free email provider"
    )
    is_newly_registered: bool = Field(default=False, description="Domain registered within 30 days")
    lookalike_domain: str | None = Field(
        default=None, description="Similar legitimate domain if spoofing detected"
    )
    header_from_mismatch: bool = Field(
        default=False,
        description="True if Header-From and Envelope-From differ",
    )


class AuthenticationResults(BaseModel):
    """SPF / DKIM / DMARC authentication results."""

    spf_result: AuthResultEnum = Field(..., description="SPF check result")
    spf_details: str | None = Field(default=None, description="SPF mechanism matched")
    dkim_result: AuthResultEnum = Field(..., description="DKIM signature result")
    dkim_selector: str | None = Field(default=None, description="DKIM selector used")
    dkim_domain: str | None = Field(default=None, description="Domain the DKIM signature covers")
    dmarc_result: AuthResultEnum = Field(..., description="DMARC policy result")
    dmarc_policy: str | None = Field(
        default=None, description="DMARC policy applied (none/quarantine/reject)"
    )
    arc_result: AuthResultEnum | None = Field(
        default=None, description="ARC chain validation result"
    )
    authentication_summary: str = Field(
        ..., description="Human-readable summary of all auth results"
    )


class GeoLocation(BaseModel):
    """Geographic location for a given IP address."""

    ip: str = Field(..., description="IP address")
    country: str | None = Field(default=None)
    country_code: str | None = Field(default=None)
    region: str | None = Field(default=None)
    city: str | None = Field(default=None)
    latitude: float | None = Field(default=None)
    longitude: float | None = Field(default=None)
    isp: str | None = Field(default=None, description="Internet Service Provider")
    org: str | None = Field(default=None, description="Organization")
    asn: str | None = Field(default=None, description="Autonomous System Number")
    is_tor: bool = Field(default=False, description="IP is a Tor exit node")
    is_vpn: bool = Field(default=False, description="IP is a known VPN endpoint")
    is_proxy: bool = Field(default=False, description="IP is a known proxy")
    is_datacenter: bool = Field(default=False, description="IP belongs to a datacenter")


class MaliciousIP(BaseModel):
    """A malicious or suspicious IP indicator."""

    ip: str = Field(..., description="IP address")
    threat_score: float = Field(..., ge=0.0, le=100.0, description="Threat score 0-100")
    threat_categories: list[str] = Field(default_factory=list, description="Threat category tags")
    reputation_source: list[str] = Field(
        default_factory=list, description="Threat intel sources that flagged this IP"
    )
    geo: GeoLocation | None = Field(default=None, description="Geographic location data")
    first_seen: datetime | None = Field(default=None)
    last_seen: datetime | None = Field(default=None)
    abuse_reports: int = Field(default=0, description="Number of abuse reports")


class MaliciousURL(BaseModel):
    """A malicious or suspicious URL indicator."""

    url: str = Field(..., description="Full URL found in email")
    domain: str = Field(..., description="Extracted domain")
    threat_score: float = Field(..., ge=0.0, le=100.0, description="URL threat score 0-100")
    threat_categories: list[str] = Field(default_factory=list)
    redirect_chain: list[str] = Field(
        default_factory=list, description="URL redirect chain if followed"
    )
    final_destination: str | None = Field(default=None, description="Final resolved URL")
    is_phishing_kit: bool = Field(default=False)
    is_credential_harvester: bool = Field(default=False)
    screenshot_url: str | None = Field(
        default=None, description="URL of page screenshot (if captured)"
    )
    reputation_sources: list[str] = Field(default_factory=list)


class ReputationScore(BaseModel):
    """Reputation data for a domain or IP from threat intel feeds."""

    entity: str = Field(..., description="Domain, IP, or URL being scored")
    entity_type: str = Field(..., description="Type: domain | ip | url | email")
    score: float = Field(..., ge=0.0, le=100.0, description="Reputation score 0-100")
    sources: list[str] = Field(default_factory=list, description="Intel sources checked")
    categories: list[str] = Field(default_factory=list, description="Threat categories")
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_blacklisted: bool = Field(default=False)
    blacklist_count: int = Field(default=0)


class TimelineEvent(BaseModel):
    """A single event in the email's investigation timeline."""

    timestamp: datetime = Field(..., description="Event timestamp (UTC)")
    event_type: str = Field(
        ..., description="Type: RECEIVED | FORWARDED | DELIVERED | BLOCKED | ANALYZED"
    )
    description: str = Field(..., description="Human-readable event description")
    actor: str | None = Field(default=None, description="Server/system that generated this event")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional structured metadata"
    )


class CorrelationNode(BaseModel):
    """A node in the threat correlation graph."""

    node_id: str = Field(..., description="Unique node identifier")
    node_type: str = Field(..., description="Type: ip | domain | email | url | actor")
    label: str = Field(..., description="Display label")
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    attributes: dict[str, Any] = Field(default_factory=dict)


class CorrelationEdge(BaseModel):
    """An edge in the threat correlation graph."""

    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    relationship: str = Field(
        ..., description="Relationship type: SENDS_FROM | RESOLVES_TO | LINKED_TO | etc."
    )
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Confidence in this relationship"
    )
    evidence: str | None = Field(
        default=None, description="Supporting evidence for this relationship"
    )


class CorrelationGraph(BaseModel):
    """Full threat correlation graph for the investigation."""

    nodes: list[CorrelationNode] = Field(default_factory=list)
    edges: list[CorrelationEdge] = Field(default_factory=list)


class InvestigationEvidence(BaseModel):
    """Raw evidence artifacts collected during investigation."""

    raw_headers: str = Field(..., description="Complete raw email headers")
    parsed_headers: dict[str, Any] = Field(
        default_factory=dict, description="Parsed header key-value pairs"
    )
    email_body_text: str | None = Field(default=None, description="Plain text email body")
    email_body_html: str | None = Field(default=None, description="HTML email body (sanitised)")
    attachments: list[dict[str, Any]] = Field(
        default_factory=list, description="Attachment metadata list"
    )
    extracted_urls: list[str] = Field(
        default_factory=list, description="All URLs extracted from body/headers"
    )
    extracted_ips: list[str] = Field(
        default_factory=list, description="All IPs extracted from headers"
    )
    hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic hashes: md5, sha1, sha256 of email body",
    )


# ---------------------------------------------------------------------------
# Root investigation payload (arrives from Backend)
# ---------------------------------------------------------------------------


class InvestigationPayload(BaseModel):
    """
    Complete investigation data assembled by the Backend API.
    This is the single input to the Reports Engine.
    The Reports Engine never queries the database directly.
    """

    investigation_id: str = Field(..., description="Unique investigation ID")
    case_summary: CaseSummary
    risk_score: RiskScore
    sender_analysis: SenderAnalysis
    authentication: AuthenticationResults
    malicious_ips: list[MaliciousIP] = Field(default_factory=list)
    malicious_urls: list[MaliciousURL] = Field(default_factory=list)
    reputation_scores: list[ReputationScore] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    correlation_graph: CorrelationGraph = Field(default_factory=CorrelationGraph)
    evidence: InvestigationEvidence

    @model_validator(mode="after")
    def ensure_ids_consistent(self) -> InvestigationPayload:
        if self.case_summary.investigation_id != self.investigation_id:
            raise ValueError("investigation_id mismatch between root and case_summary")
        return self


# ---------------------------------------------------------------------------
# Output report model
# ---------------------------------------------------------------------------


class JSONReport(BaseModel):
    """
    Final structured JSON forensic report.
    This is the output contract of the Reports Engine.
    """

    report_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique report identifier (UUID v4)",
    )
    report_version: str = Field(default="1.0.0", description="Report schema version")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Report generation timestamp (UTC ISO 8601)",
    )
    generated_by: str = Field(
        default="TraceMail AI — Reports Engine v1.0",
        description="System that generated this report",
    )
    investigation_id: str = Field(..., description="Source investigation ID")
    report_hash: str = Field(
        default="", description="SHA-256 of report content for integrity verification"
    )

    # The 10 required sections
    case_summary: CaseSummary
    risk_score: RiskScore
    sender_analysis: SenderAnalysis
    authentication: AuthenticationResults
    malicious_ips: list[MaliciousIP]
    malicious_urls: list[MaliciousURL]
    reputation_scores: list[ReputationScore]
    timeline: list[TimelineEvent]
    correlation_graph: CorrelationGraph
    evidence: InvestigationEvidence

    def model_post_init(self, context: Any, /) -> None:
        """Compute and attach SHA-256 integrity hash after construction."""
        if not self.report_hash:
            payload = self.model_dump_json(exclude={"report_hash", "report_id", "generated_at"})
            self.report_hash = hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# JSON Report Generator
# ---------------------------------------------------------------------------


class JSONReportGenerator:
    """
    Converts an assembled InvestigationPayload into a signed JSONReport.

    Usage:
        generator = JSONReportGenerator()
        report    = generator.generate(payload)
        output    = generator.to_json(report)

    The generator is stateless and thread-safe.
    """

    REPORT_VERSION = "1.0.0"

    def generate(self, payload: InvestigationPayload) -> JSONReport:
        """
        Build a JSONReport from the assembled InvestigationPayload.

        Args:
            payload: Fully validated InvestigationPayload from the Backend.

        Returns:
            JSONReport: Complete, hash-signed forensic report.
        """
        report = JSONReport(
            report_version=self.REPORT_VERSION,
            investigation_id=payload.investigation_id,
            case_summary=payload.case_summary,
            risk_score=payload.risk_score,
            sender_analysis=payload.sender_analysis,
            authentication=payload.authentication,
            malicious_ips=payload.malicious_ips,
            malicious_urls=payload.malicious_urls,
            reputation_scores=payload.reputation_scores,
            timeline=sorted(payload.timeline, key=lambda e: e.timestamp),
            correlation_graph=payload.correlation_graph,
            evidence=payload.evidence,
        )
        return report

    def to_json(
        self,
        report: JSONReport,
        indent: int = 2,
        exclude_evidence_body: bool = False,
    ) -> str:
        """
        Serialise a JSONReport to a formatted JSON string.

        Args:
            report              : The report to serialise.
            indent              : JSON indentation (default 2).
            exclude_evidence_body: If True, omits raw HTML/text bodies
                                   for reduced payload size.

        Returns:
            str: UTF-8 encoded JSON string.
        """
        if exclude_evidence_body:
            # We build the dict manually to strip body fields
            data = json.loads(report.model_dump_json())
            data["evidence"].pop("email_body_text", None)
            data["evidence"].pop("email_body_html", None)
            return json.dumps(data, indent=indent, ensure_ascii=False)

        return report.model_dump_json(indent=indent)

    def to_dict(self, report: JSONReport) -> dict[str, Any]:
        """Return the report as a plain Python dict."""
        return json.loads(report.model_dump_json())

    def validate_payload(self, raw_data: dict[str, Any]) -> InvestigationPayload:
        """
        Validate raw dict input (e.g. from HTTP request body) into an
        InvestigationPayload.  Raises ValidationError on failure.

        Args:
            raw_data: Raw dictionary from FastAPI request body.

        Returns:
            InvestigationPayload: Validated model instance.
        """
        return InvestigationPayload.model_validate(raw_data)
