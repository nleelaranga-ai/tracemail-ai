"""
TraceMail AI — Shared Interfaces Package
"""

from shared.interfaces.contracts import (
    IPThreatResponse,
    URLThreatRequest,
    URLThreatResponse,
    AuthCheckRequest,
    AuthCheckResponse,
    UnifiedThreatReport,
    AIPhishingRequest,
    AIPhishingResponse,
    AIEntities,
    GeoJSONFeature,
    GeoJSONFeatureCollection,
    TimelineEvent,
    GraphNode,
    GraphEdge,
    AttackGraphResponse,
    InvestigationDetailResponse,
)

__all__ = [
    "IPThreatResponse",
    "URLThreatRequest",
    "URLThreatResponse",
    "AuthCheckRequest",
    "AuthCheckResponse",
    "UnifiedThreatReport",
    "AIPhishingRequest",
    "AIPhishingResponse",
    "AIEntities",
    "GeoJSONFeature",
    "GeoJSONFeatureCollection",
    "TimelineEvent",
    "GraphNode",
    "GraphEdge",
    "AttackGraphResponse",
    "InvestigationDetailResponse",
]
