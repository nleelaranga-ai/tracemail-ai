"""
TraceMail AI — Maps Engine Integration & Section 6 Contracts Test Suite
Validates maps_engine package, ScanService delegation, endpoint responses,
and standalone microservice capabilities.
"""
import pytest
from fastapi.testclient import TestClient

from maps_engine.geo.geo_builder import build_geojson
from maps_engine.timeline.timeline_builder import build_timeline
from maps_engine.graph.graph_builder import build_attack_graph
from maps_engine.main import app as maps_app
from backend.services.scan_service import ScanService
from backend.main import app as backend_app


@pytest.fixture
def sample_hops():
    return [
        {
            "server": "mail-gw-01.frankfurt.net",
            "ip": "185.220.101.4",
            "city": "Frankfurt",
            "lat": 50.1109,
            "lon": 8.6821,
            "timestamp": "2026-09-06T09:58:12Z",
            "malicious": True
        },
        {
            "server": "relay-inbound.blr.google.com",
            "ip": "142.250.1.27",
            "city": "Bengaluru",
            "lat": 12.9716,
            "lon": 77.5946,
            "timestamp": "2026-09-06T09:58:15Z",
            "malicious": False
        }
    ]


def test_maps_engine_geojson_builder(sample_hops):
    """Test GeoJSON builder produces points and flight paths matching Leaflet contract."""
    geojson = build_geojson(sample_hops)
    assert geojson["type"] == "FeatureCollection"
    assert len(geojson["features"]) == 3  # 2 points + 1 connecting linestring

    point1 = geojson["features"][0]
    assert point1["geometry"]["type"] == "Point"
    assert point1["geometry"]["coordinates"] == [8.6821, 50.1109]
    assert point1["properties"]["ip"] == "185.220.101.4"
    assert point1["properties"]["malicious"] is True

    line = geojson["features"][2]
    assert line["geometry"]["type"] == "LineString"
    assert line["geometry"]["coordinates"] == [[8.6821, 50.1109], [77.5946, 12.9716]]
    assert line["properties"]["type"] == "email_path"


def test_maps_engine_geojson_missing_locations():
    """Hops without valid coordinates should be safely skipped."""
    hops = [{"ip": "10.0.0.1", "city": "Internal", "server": "local"}]
    geojson = build_geojson(hops)
    assert geojson["type"] == "FeatureCollection"
    assert len(geojson["features"]) == 0


def test_maps_engine_timeline_builder_sorting():
    """Test timeline builder sorts out-of-order hops chronologically."""
    unordered = [
        {"server": "srv2", "ip": "2.2.2.2", "timestamp": "2026-09-06T10:05:00Z", "malicious": False},
        {"server": "srv1", "ip": "1.1.1.1", "timestamp": "2026-09-06T10:01:00Z", "malicious": True},
    ]
    timeline = build_timeline(unordered)
    assert len(timeline) == 2
    assert timeline[0]["step"] == 1
    assert timeline[0]["ip"] == "1.1.1.1"
    assert timeline[1]["step"] == 2
    assert timeline[1]["ip"] == "2.2.2.2"


def test_maps_engine_attack_graph_topology(sample_hops):
    """Test attack graph topology constructs valid DAG from sender to recipient."""
    graph = build_attack_graph(
        sample_hops,
        sender="attacker@phish.com",
        recipient="target@company.org",
        is_phishing=True
    )
    assert len(graph["nodes"]) == 4
    assert len(graph["edges"]) == 3

    # Nodes validation
    node_ids = [n["id"] for n in graph["nodes"]]
    assert node_ids == ["sender", "hop1", "hop2", "victim"]
    assert graph["nodes"][0]["malicious"] is True  # sender flagged phishing
    assert graph["nodes"][1]["malicious"] is True  # hop 1 flagged malicious
    assert graph["nodes"][2]["malicious"] is False # hop 2 clean
    assert graph["nodes"][3]["malicious"] is False # victim

    # Edges validation
    assert graph["edges"][0] == {"from": "sender", "to": "hop1"}
    assert graph["edges"][1] == {"from": "hop1", "to": "hop2"}
    assert graph["edges"][2] == {"from": "hop2", "to": "victim"}


def test_scan_service_delegates_to_maps_engine(sample_hops):
    """Verify ScanService class methods properly invoke maps_engine under the hood."""
    gj = ScanService.generate_geojson(sample_hops, origin_city="Frankfurt")
    assert gj["type"] == "FeatureCollection"
    assert len(gj["features"]) == 3

    tl = ScanService.generate_timeline(sample_hops)
    assert len(tl) == 2
    assert tl[0]["step"] == 1

    ag = ScanService.generate_attack_graph("a@b.com", "c@d.com", sample_hops, is_phishing=True)
    assert len(ag["nodes"]) == 4
    assert ag["nodes"][0]["malicious"] is True


def test_maps_engine_microservice_endpoints(sample_hops):
    """Test standalone Maps Engine FastAPI service running on port 8003."""
    client = TestClient(maps_app)

    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["service"] == "maps-engine"

    # POST /api/geo/build-map
    res_map = client.post("/api/geo/build-map", json={"hops": sample_hops})
    assert res_map.status_code == 200
    assert res_map.json()["type"] == "FeatureCollection"

    # POST /api/geo/build-timeline
    res_tl = client.post("/api/geo/build-timeline", json={"hops": sample_hops})
    assert res_tl.status_code == 200
    assert len(res_tl.json()) == 2

    # POST /api/geo/build-graph
    res_ag = client.post("/api/geo/build-graph", json={
        "hops": sample_hops,
        "sender": "attacker@evil.com",
        "recipient": "victim@safe.com",
        "is_phishing": True
    })
    assert res_ag.status_code == 200
    assert len(res_ag.json()["nodes"]) == 4


def test_backend_maps_endpoints_fallback_and_data():
    """Verify backend GET /api/geo/* endpoints return valid fallback structures."""
    client = TestClient(backend_app)

    # Non-existent scan returns empty FeatureCollection
    res_map = client.get("/api/geo/map/non_existent_id_999")
    assert res_map.status_code == 200
    assert res_map.json() == {"type": "FeatureCollection", "features": []}

    # Non-existent timeline returns empty list
    res_tl = client.get("/api/geo/timeline/non_existent_id_999")
    assert res_tl.status_code == 200
    assert res_tl.json() == []

    # Non-existent attack graph returns empty dict
    res_ag = client.get("/api/geo/graph/non_existent_id_999")
    assert res_ag.status_code == 200
    assert res_ag.json() == {"nodes": [], "edges": []}
