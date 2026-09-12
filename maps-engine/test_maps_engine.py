from geo.geo_builder import build_geojson
from timeline.timeline_builder import build_timeline
from graph.graph_builder import build_attack_graph
hops = [
    {
        "server": "mail.example.com",
        "ip": "185.220.101.4",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "timestamp": "2026-09-06T09:58:12Z",
        "malicious": True
    },
    {
        "server": "relay.example.com",
        "ip": "142.250.1.27",
        "city": "Bengaluru",
        "lat": 12.9716,
        "lon": 77.5946,
        "timestamp": "2026-09-06T09:58:15Z",
        "malicious": False
    }
]
geojson = build_geojson(hops)

print("GEOJSON RESULT:")
print(geojson)
timeline = build_timeline(hops)

print("\nTIMELINE RESULT:")
print(timeline)
graph = build_attack_graph(
    hops,
    sender="attacker@example.com",
    recipient="victim@example.com"
)

print("\nATTACK GRAPH RESULT:")
print(graph)
# Basic checks
assert geojson["type"] == "FeatureCollection"
assert len(geojson["features"]) == 3

assert timeline[0]["step"] == 1
assert timeline[1]["step"] == 2
assert timeline[0]["timestamp"] < timeline[1]["timestamp"]

assert len(graph["nodes"]) == 4
assert len(graph["edges"]) == 3

print("\nALL MAPS ENGINE TESTS PASSED!")
# Test hop with missing location
hops_with_missing_location = [
    {
        "server": "unknown.example.com",
        "ip": "10.0.0.1",
        "city": "Unknown",
        "timestamp": "2026-09-06T10:00:00Z",
        "malicious": False
    }
]

geojson_missing = build_geojson(hops_with_missing_location)

assert geojson_missing["type"] == "FeatureCollection"
assert len(geojson_missing["features"]) == 0

print("MISSING LOCATION TEST PASSED!")
# Test timeline sorting
unordered_hops = [
    {
        "server": "server-2.example.com",
        "ip": "2.2.2.2",
        "timestamp": "2026-09-06T10:05:00Z",
        "malicious": False
    },
    {
        "server": "server-1.example.com",
        "ip": "1.1.1.1",
        "timestamp": "2026-09-06T10:01:00Z",
        "malicious": True
    }
]

sorted_timeline = build_timeline(unordered_hops)

assert sorted_timeline[0]["ip"] == "1.1.1.1"
assert sorted_timeline[1]["ip"] == "2.2.2.2"

print("TIMELINE SORTING TEST PASSED!")
# Test malicious hop in attack graph
graph_test = build_attack_graph(
    hops,
    sender="attacker@example.com",
    recipient="victim@example.com"
)

assert graph_test["nodes"][1]["malicious"] is True
assert graph_test["nodes"][2]["malicious"] is False

print("ATTACK GRAPH MALICIOUS TEST PASSED!")
# Maps Engine Tests
# Tests GeoJSON, Timeline, and Attack Graph generation