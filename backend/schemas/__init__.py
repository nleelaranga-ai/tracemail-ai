# backend/schemas/__init__.py
from .auth_schema import LoginRequest, RegisterRequest, AuthResponse, UserProfile
from .email_schema import EmailUploadResponse, EmailParsedData, HeaderInfo, AttachmentInfo
from .scan_schema import ScanEmailRequest, ScanUrlRequest, ScanDomainRequest, ScanResultResponse
from .report_schema import (
    InvestigationDetailResponse,
    InvestigationSummary,
    AIResult,
    ExtractedEntities,
    ThreatItem,
    TimelineStep,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
)
from .response_schema import APIResponse, HealthResponse
