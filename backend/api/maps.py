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
    if inv and inv.geojson_map:
        return inv.geojson_map

    if inv:
        lat = float(inv.latitude or 20.5937)
        lon = float(inv.longitude or 78.9629)
        city = inv.origin_city or inv.city or "Transmission Node"
        ip = inv.origin_ip or inv.ip or "Unknown IP"
        is_mal = inv.verdict == "phishing"
        return {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {"hop": 1, "ip": ip, "city": city, "malicious": is_mal}
                }
            ]
        }

    return {
        "type": "FeatureCollection",
        "features": []
    }


@router.get("/api/geo/timeline/{id}", response_model=List[TimelineStep])
def get_investigation_timeline(id: str, db: Session = Depends(get_db)):
    """Returns chronological timeline of mail server hops."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if inv and inv.hop_timeline:
        return [TimelineStep(**step) for step in inv.hop_timeline]

    if inv:
        ip = inv.origin_ip or inv.ip or "127.0.0.1"
        ts = inv.received_at.isoformat() if inv.received_at else "2026-09-11T00:00:00Z"
        is_mal = inv.verdict == "phishing"
        return [
            TimelineStep(
                step=1,
                server=f"mta-{inv.domain or 'origin'}.network",
                ip=ip,
                timestamp=ts,
                malicious=is_mal
            )
        ]

    return []


@router.get("/api/geo/graph/{id}")
def get_investigation_attack_graph(id: str, db: Session = Depends(get_db)):
    """Returns attack graph topology nodes and edges."""
    inv = db.query(Investigation).filter(Investigation.id == id).first()
    if inv and inv.attack_graph:
        return inv.attack_graph

    if inv:
        is_mal = inv.verdict == "phishing"
        sender_lbl = inv.sender or "sender@domain.com"
        victim_lbl = inv.recipient or "analyst@tracemail.local"
        hop_lbl = f"{inv.origin_ip or inv.ip or 'Gateway'} ({inv.origin_city or inv.city or 'Relay'})"
        return {
            "nodes": [
                {"id": "sender", "label": sender_lbl, "type": "sender", "malicious": is_mal},
                {"id": "hop1", "label": hop_lbl, "type": "relay", "malicious": is_mal},
                {"id": "victim", "label": victim_lbl, "type": "recipient", "malicious": False}
            ],
            "edges": [
                {"from": "sender", "to": "hop1"},
                {"from": "hop1", "to": "victim"}
            ]
        }

    return {"nodes": [], "edges": []}


@router.get("/api/v1/maps/origin/{scan_id}")
def get_origin_by_scan_id(scan_id: str, db: Session = Depends(get_db)):
    """Returns origin coordinates and location for a specific scan ID."""
    inv = db.query(Investigation).filter(Investigation.id == scan_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    geoip_data = (inv.threat_intel or {}).get("geoip", {})
    return {
        "scan_id": inv.id,
        "ip": inv.origin_ip or geoip_data.get("ip", "127.0.0.1"),
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
    target_ip = ip or "8.8.8.8"
    threat = await ScanService.query_ip_threat(target_ip)
    return {
        "ip": target_ip,
        "country": threat.get("country", "United States"),
        "city": threat.get("city", "Ashburn"),
        "latitude": threat.get("lat", 39.0438),
        "longitude": threat.get("lon", -77.4874)
    }
