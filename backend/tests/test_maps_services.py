"""
TraceMail AI Backend — Google Maps Platform Test Suite
Validates ip_service, maps_service (Google Geocoding, Google Directions, Google Places),
Google Polyline Decoding, 30-Day Caching, and all /maps/* REST endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from backend.services.ip_service import ip_service
from backend.services.maps_service import maps_service, MapsService
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# 1. IP Geolocation Service (ip-api.com)
# ============================================================================

@pytest.mark.asyncio
async def test_ip_service_private_ip():
    """Private and loopback IPs should be resolved safely without network errors."""
    res = await ip_service.get_location("127.0.0.1")
    assert res["status"] == "success"
    assert res["ip"] == "127.0.0.1"
    assert "Internal" in res["country"] or res["country"] == "Internal Network"
    assert res["latitude"] != 0.0


@pytest.mark.asyncio
async def test_ip_service_known_ip_and_caching():
    """Known benchmark IPs should resolve to Frankfurt, Germany and cache."""
    res1 = await ip_service.get_location("185.220.101.4")
    assert res1["status"] == "success"
    assert res1["country"] == "Germany"
    assert res1["city"] in ["Frankfurt", "Brandenburg an der Havel", "Berlin"]
    assert res1["latitude"] != 0.0
    assert res1["longitude"] != 0.0

    # Second call must hit the 30-day cache
    res2 = await ip_service.get_location("185.220.101.4")
    assert res2["cached"] is True


# ============================================================================
# 2. Google Maps Platform Geocoding Service
# ============================================================================

@pytest.mark.asyncio
async def test_google_forward_geocoding():
    """City and country should resolve to valid lat/lon."""
    res = await maps_service.geocode(city="Vijayawada", country="India")
    assert abs(res["latitude"] - 16.50) < 0.2
    assert abs(res["longitude"] - 80.64) < 0.2
    assert "Vijayawada" in res["display_name"]

    # Repeat should be cached
    cached_res = await maps_service.geocode(city="Vijayawada", country="India")
    assert cached_res["cached"] is True


@pytest.mark.asyncio
async def test_google_reverse_geocoding():
    """Coordinates should reverse-resolve to location details."""
    res = await maps_service.reverse_geocode(lat=50.1109, lon=8.6821)
    assert res["latitude"] == 50.1109
    assert res["longitude"] == 8.6821
    assert "Frankfurt" in res["display_name"]


# ============================================================================
# 3. Google Encoded Polyline Algorithm Decoding
# ============================================================================

def test_google_polyline_decoding():
    """Validates standard Google encoded polyline decompression."""
    # Encoded polyline for points: (38.5, -120.2), (40.7, -120.95), (43.252, -126.453)
    encoded = "_p~iF~ps|U_ulLnnqC_mqNvxq`@"
    decoded = MapsService.decode_polyline(encoded)
    assert len(decoded) == 3
    assert abs(decoded[0][0] - 38.5) < 0.001
    assert abs(decoded[0][1] - (-120.2)) < 0.001
    assert abs(decoded[1][0] - 40.7) < 0.001
    assert abs(decoded[2][0] - 43.252) < 0.001


# ============================================================================
# 4. Google Directions Attack Route Service
# ============================================================================

@pytest.mark.asyncio
async def test_google_attack_route():
    """Computes multi-hop trajectory between attack origin and victim."""
    coords = [(50.1109, 8.6821), (12.9716, 77.5946), (16.5062, 80.6480)]
    res = await maps_service.get_route(coords)
    assert res["distance"] > 0
    assert res["hops_count"] == 3
    assert len(res["geometry"]) >= 3
    assert res["provider"] == "Google Maps Platform"
    
    # Geometry points must be in [lat, lon] format
    first_pt = res["geometry"][0]
    assert len(first_pt) == 2
    assert abs(first_pt[0] - 50.11) < 0.2


# ============================================================================
# 5. Google Places Nearby Infrastructure Service
# ============================================================================

@pytest.mark.asyncio
async def test_google_nearby_places():
    """Discovers nearby infrastructure around suspicious coordinates."""
    res = await maps_service.get_places(lat=50.1109, lon=8.6821, radius=5000)
    assert res["center_latitude"] == 50.1109
    assert res["radius_meters"] == 5000
    assert len(res["places"]) > 0
    assert res["provider"] == "Google Maps Platform"
    first_place = res["places"][0]
    assert "name" in first_place
    assert "amenity" in first_place
    assert "latitude" in first_place
    assert "distance_meters" in first_place


# ============================================================================
# 6. Master Maps Service Orchestration
# ============================================================================

@pytest.mark.asyncio
async def test_maps_service_build_investigation_map():
    """Combines markers, routes, and heatmap into unified payload."""
    from backend.database.connection import SessionLocal
    db = SessionLocal()
    try:
        res = await maps_service.build_investigation_map("test-case-id", db)
        assert res["scan_id"] == "test-case-id"
        assert len(res["markers"]) >= 3
        assert len(res["routes"]) >= 1
        assert len(res["heatmap"]) >= 3
        assert res["summary"]["provider"] == "Google Maps Platform"
        assert res["summary"]["billing_required"] is True

        # Validate Marker Types and Color Coding
        types = [m["type"] for m in res["markers"]]
        colors = [m["color"] for m in res["markers"]]
        assert "attacker" in types
        assert "victim" in types
        assert "relay" in types
        assert "#ef4444" in colors  # 🔴 Red
        assert "#3b82f6" in colors  # 🔵 Blue
        assert "#f97316" in colors  # 🟠 Orange
    finally:
        db.close()


# ============================================================================
# 7. REST API Endpoints Contract Tests
# ============================================================================

def test_endpoint_maps_location(client):
    res = client.get("/maps/location/185.220.101.4")
    assert res.status_code == 200
    data = res.json()
    assert data["country"] == "Germany"
    assert data["city"] in ["Frankfurt", "Brandenburg an der Havel", "Berlin"]
    assert data["latitude"] != 0.0


def test_endpoint_maps_geocode(client):
    res = client.get("/maps/geocode?city=Bengaluru&country=India")
    assert res.status_code == 200
    data = res.json()
    assert "Bengaluru" in data["display_name"]
    assert abs(data["latitude"] - 12.97) < 0.2


def test_endpoint_maps_reverse(client):
    res = client.get("/maps/reverse?lat=50.1109&lon=8.6821")
    assert res.status_code == 200
    data = res.json()
    assert "Frankfurt" in data["display_name"]


def test_endpoint_maps_route(client):
    res = client.get("/maps/route?coords=50.1109,8.6821;16.5062,80.6480")
    assert res.status_code == 200
    data = res.json()
    assert data["distance"] > 0
    assert len(data["geometry"]) >= 2
    assert data["provider"] == "Google Maps Platform"


def test_endpoint_maps_places(client):
    res = client.get("/maps/places?lat=50.1109&lon=8.6821&radius=5000")
    assert res.status_code == 200
    data = res.json()
    assert len(data["places"]) > 0
    assert data["provider"] == "Google Maps Platform"


def test_endpoint_maps_investigation(client):
    res = client.get("/maps/investigation/test-inv-001")
    assert res.status_code == 200
    data = res.json()
    assert "markers" in data
    assert "routes" in data
    assert "heatmap" in data
    assert data["summary"]["provider"] == "Google Maps Platform"
    assert data["summary"]["billing_required"] is True


def test_endpoint_api_v1_compatibility(client):
    """Verify dual-mounting under /api/v1/maps/* works identically."""
    res1 = client.get("/api/v1/maps/location/8.8.8.8")
    assert res1.status_code == 200
    assert res1.json()["country"] == "United States"

    res2 = client.get("/api/v1/maps/investigation/test-inv-002")
    assert res2.status_code == 200
    assert len(res2.json()["markers"]) >= 3
