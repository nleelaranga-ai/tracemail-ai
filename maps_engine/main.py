"""
TraceMail AI — Maps & Attack Graph Engine Microservice (Port 8003)
Provides GeoJSON email path creation, chronological hop timeline,
and attack topology graph construction for TraceMail AI forensics platform.
"""
import sys
from pathlib import Path

# Ensure package is importable when executed directly
_pkg_root = str(Path(__file__).resolve().parent.parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from maps_engine.geo.geo_builder import build_geojson
from maps_engine.timeline.timeline_builder import build_timeline
from maps_engine.graph.graph_builder import build_attack_graph

app = FastAPI(
    title="TraceMail AI — Maps & Attack Graph Engine",
    version="2.0.0",
    description="Spatial telemetry, hop timeline, and attack topology builder for TraceMail AI."
)


class GeoJsonRequest(BaseModel):
    hops: List[Dict[str, Any]] = Field(default_factory=list, description="List of email relay hops with coordinates")
    origin_city: Optional[str] = Field("Origin Node", description="Fallback city name")
    origin_lat: Optional[float] = Field(0.0, description="Fallback latitude")
    origin_lon: Optional[float] = Field(0.0, description="Fallback longitude")


class TimelineRequest(BaseModel):
    hops: List[Dict[str, Any]] = Field(default_factory=list, description="List of email relay hops")
    default_ip: Optional[str] = Field("Origin Host", description="Fallback IP address")


class AttackGraphRequest(BaseModel):
    hops: List[Dict[str, Any]] = Field(default_factory=list, description="List of email relay hops")
    sender: Optional[str] = Field(None, description="Sender email or origin host")
    recipient: Optional[str] = Field(None, description="Recipient email or destination mailbox")
    is_phishing: Optional[bool] = Field(False, description="Whether transmission is flagged as phishing")


@app.get("/health")
def health_check():
    """Service health probe matching docker-compose expectations."""
    return {
        "status": "ok",
        "service": "maps-engine",
        "version": "2.0.0"
    }


@app.post("/api/geo/build-map")
def api_build_geojson(req: GeoJsonRequest):
    """Build GeoJSON FeatureCollection from hops."""
    return build_geojson(
        hops=req.hops,
        origin_city=req.origin_city or "Origin Node",
        origin_lat=req.origin_lat or 0.0,
        origin_lon=req.origin_lon or 0.0
    )


@app.post("/api/geo/build-timeline")
def api_build_timeline(req: TimelineRequest):
    """Build chronological timeline steps from hops."""
    return build_timeline(
        hops=req.hops,
        default_ip=req.default_ip or "Origin Host"
    )


@app.post("/api/geo/build-graph")
def api_build_graph(req: AttackGraphRequest):
    """Build interactive attack topology graph nodes and edges."""
    return build_attack_graph(
        hops=req.hops,
        sender=req.sender,
        recipient=req.recipient,
        is_phishing=req.is_phishing or False
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
