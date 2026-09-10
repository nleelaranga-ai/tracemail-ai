"""
TraceMail AI Backend — Maps, Timeline & Attack Graph Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List, Dict, Any

from backend.database.connection import get_db, Session
from backend.models.scan import Investigation
from backend.schemas.report_schema import TimelineStep, AttackGraph
from backend.services.scan_service import ScanService

router = APIRouter(tags=["Maps & Visualization"])


@router.get("/api/geo/map/{id}")
def get_investigation_map(id: str, db: Session = Depends(get_db)):
    """Returns GeoJSON FeatureCollection showing email path across servers."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv or not inv.geojson_map:
        # Fallback sample GeoJSON
        return {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [8.68, 50.11]},
                    "properties": {"hop": 1, "ip": "185.220.101.4", "city": "Frankfurt", "malicious": True}
                },
                {
                    "type": "Feature",
                    "geometry": {"type": "LineString", "coordinates": [[8.68, 50.11], [77.59, 12.97]]},
                    "properties": {"from": "Frankfurt", "to": "Bengaluru"}
                }
            ]
        }
    return inv.geojson_map


@router.get("/api/geo/timeline/{id}", response_model=List[TimelineStep])
def get_investigation_timeline(id: str, db: Session = Depends(get_db)):
    """Returns chronological timeline of mail server hops."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv or not inv.hop_timeline:
        return [
            TimelineStep(
                step=1,
                server="mail.sketchy-relay.net",
                ip="185.220.101.4",
                timestamp="2026-09-07T14:30:00Z",
                malicious=True
            ),
            TimelineStep(
                step=2,
                server="mx.gmail.com",
                ip="142.250.1.27",
                timestamp="2026-09-07T14:30:03Z",
                malicious=False
            )
        ]
    return [TimelineStep(**step) for step in inv.hop_timeline]


@router.get("/api/geo/graph/{id}")
def get_investigation_attack_graph(id: str, db: Session = Depends(get_db)):
    """Returns attack graph topology nodes and edges."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if not inv or not inv.attack_graph:
        return {
            "nodes": [
                {"id": "sender", "label": "unknown@sketchy-relay.net", "type": "sender", "malicious": True},
                {"id": "hop1", "label": "185.220.101.4 (Frankfurt)", "type": "relay", "malicious": True},
                {"id": "victim", "label": "analyst@target.org", "type": "recipient", "malicious": False}
            ],
            "edges": [
                {"from": "sender", "to": "hop1"},
                {"from": "hop1", "to": "victim"}
            ]
        }
    return inv.attack_graph


@router.get("/api/v1/maps/origin/{scan_id}")
def get_origin_by_scan_id(scan_id: str, db: Session = Depends(get_db)):
    """Returns origin coordinates and location for a specific scan ID."""
    inv = db.query(Investigation).filter(Investigation.id == scan_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    geoip_data = (inv.threat_intel or {}).get("geoip", {})
    return {
        "scan_id": inv.id,
        "ip": inv.origin_ip or geoip_data.get("ip", "185.220.101.4"),
        "country": inv.origin_country or geoip_data.get("country", "Unknown"),
        "city": inv.origin_city or geoip_data.get("city", "Unknown"),
        "latitude": inv.latitude if inv.latitude is not None else geoip_data.get("latitude", 0.0),
        "longitude": inv.longitude if inv.longitude is not None else geoip_data.get("longitude", 0.0),
        "isp": geoip_data.get("isp", "N/A"),
        "asn": geoip_data.get("asn", "N/A"),
        "threat_score": inv.threat_score if inv.threat_score is not None else inv.phishing_score,
        "risk_level": inv.risk_level or "Unknown"
    }


@router.get("/api/v1/maps/origin")
async def get_origin_coordinates(ip: Optional[str] = Query(None, description="IP address to locate")):
    """Returns origin coordinates and location for frontend visualization."""
    target_ip = ip or "185.220.101.4"
    threat = await ScanService.query_ip_threat(target_ip)
    return {
        "ip": target_ip,
        "country": threat.get("country", "Germany"),
        "city": threat.get("city", "Frankfurt"),
        "latitude": threat.get("lat", 50.1109),
        "longitude": threat.get("lon", 8.6821)
    }
