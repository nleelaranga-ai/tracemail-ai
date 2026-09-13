"""
TraceMail AI Backend — Pydantic Schemas for OpenStreetMap Geospatial Stack
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class LocationResponse(BaseModel):
    ip: str
    city: str = "Unknown"
    country: str = "Unknown"
    country_code: str = ""
    region: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = "Unknown"
    org: str = "Unknown"
    asn: str = "Unknown"
    timezone: str = "UTC"
    status: str = "success"
    cached: bool = False


class GeocodeResponse(BaseModel):
    query: str
    latitude: float
    longitude: float
    display_name: str
    boundingbox: Optional[List[str]] = None
    cached: bool = False


class ReverseGeocodeResponse(BaseModel):
    latitude: float
    longitude: float
    display_name: str
    address: Dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class RouteCoordinate(BaseModel):
    lat: float
    lon: float


class RouteResponse(BaseModel):
    distance: float = Field(..., description="Distance in meters")
    duration: float = Field(..., description="Estimated traversal duration in seconds")
    geometry: List[List[float]] = Field(..., description="Polyline coordinates as [[lat, lon], ...]")
    waypoints: List[Dict[str, Any]] = Field(default_factory=list)
    hops_count: int = 1
    provider: str = "OSRM"


class PlaceItem(BaseModel):
    name: str
    amenity: str
    latitude: float
    longitude: float
    distance_meters: Optional[float] = None


class PlacesResponse(BaseModel):
    center_latitude: float
    center_longitude: float
    radius_meters: int
    places: List[PlaceItem]
    count: int
    provider: str = "Overpass API"


class MapMarker(BaseModel):
    id: str
    label: str
    type: str = Field(..., description="attacker | victim | relay | safe")
    color: str = Field(..., description="Hex color code (#ef4444, #3b82f6, #f97316, #22c55e)")
    latitude: float
    longitude: float
    ip: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    threat_score: int = 0
    isp: Optional[str] = None
    role: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class MapRoute(BaseModel):
    id: str
    name: str
    polyline: List[List[float]] = Field(..., description="[[lat, lon], ...]")
    distance_km: float = 0.0
    is_hostile: bool = False
    color: str = "#ef4444"
    hops: List[str] = Field(default_factory=list)


class HeatmapPoint(BaseModel):
    lat: float
    lng: float
    weight: float = Field(..., description="Threat intensity weight (0 - 100)")


class InvestigationMapResponse(BaseModel):
    scan_id: str
    origin_ip: str
    origin_city: str
    origin_country: str
    threat_score: int
    risk_level: str
    markers: List[MapMarker]
    routes: List[MapRoute]
    heatmap: List[HeatmapPoint]
    nearby_places: List[PlaceItem] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
