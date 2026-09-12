"""
Unit tests for Investigation Details, Geo, Timeline, and Report Downloads
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)
DEMO_ID = "inv_paypal_phish_demo_01"


def test_get_investigation_detail_contract():
    res = client.get(f"/api/investigations/{DEMO_ID}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == DEMO_ID
    assert data["status"] == "complete"
    assert "aiResult" in data
    assert data["aiResult"]["phishingScore"] == 94
    assert len(data["threatResults"]) > 0
    assert data["mapUrl"] == f"/api/geo/map/{DEMO_ID}"
    assert data["timelineUrl"] == f"/api/geo/timeline/{DEMO_ID}"
    assert data["graphUrl"] == f"/api/geo/graph/{DEMO_ID}"
    assert data["reportUrl"] == f"/api/report/pdf/{DEMO_ID}"


def test_geo_map_and_timeline():
    map_res = client.get(f"/api/geo/map/{DEMO_ID}")
    assert map_res.status_code == 200
    assert map_res.json()["type"] == "FeatureCollection"

    time_res = client.get(f"/api/geo/timeline/{DEMO_ID}")
    assert time_res.status_code == 200
    assert len(time_res.json()) >= 1

    graph_res = client.get(f"/api/geo/graph/{DEMO_ID}")
    assert graph_res.status_code == 200
    assert "nodes" in graph_res.json()
    assert "edges" in graph_res.json()


def test_download_pdf_and_json_reports():
    pdf_res = client.get(f"/api/report/pdf/{DEMO_ID}")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 100

    json_res = client.get(f"/api/report/json/{DEMO_ID}")
    assert json_res.status_code == 200
    assert json_res.json()["report_metadata"]["investigation_id"] == DEMO_ID


def test_investigation_and_timeline_frontend_contract():
    """
    Contract test ensuring /api/investigations/{id} and /api/geo/timeline/{id}
    emit the exact shapes consumed by TimelinePanel, ThreatIntelCards, and IOCChips.
    """
    # 1. Test Hop Timeline route (used by TimelinePanel 'Mail Server Hops Route' tab)
    hop_res = client.get(f"/api/geo/timeline/{DEMO_ID}")
    assert hop_res.status_code == 200
    hops = hop_res.json()
    assert isinstance(hops, list) and len(hops) > 0
    for hop in hops:
        assert "step" in hop, "Hop must have 'step'"
        assert "server" in hop, "Hop must have 'server'"
        assert "ip" in hop, "Hop must have 'ip'"
        assert "timestamp" in hop, "Hop must have 'timestamp'"
        assert "malicious" in hop, "Hop must have 'malicious'"

    # 2. Test Investigation Details route (used by TimelinePanel 6-step lifecycle & cards)
    inv_res = client.get(f"/api/investigations/{DEMO_ID}")
    assert inv_res.status_code == 200
    data = inv_res.json()

    # Timeline contract
    assert "timeline" in data, "Response must include 'timeline'"
    assert isinstance(data["timeline"], list) and len(data["timeline"]) == 6
    for step in data["timeline"]:
        assert "step" in step, "Lifecycle step must have 'step'"
        assert "name" in step, "Lifecycle step must have 'name'"
        assert "detail" in step, "Lifecycle step must have 'detail'"
        assert "status" in step, "Lifecycle step must have 'status'"
        assert "event" in step, "Lifecycle step must have legacy 'event'"
        assert "time" in step or "timestamp" in step, "Lifecycle step must have timing"

    # Threat Intel bundle contract
    intel = data.get("threat_intel") or data.get("threatIntel") or {}
    assert "virustotal" in intel, "threat_intel must include virustotal"
    assert "whois" in intel, "threat_intel must include whois"
    assert "dns" in intel, "threat_intel must include dns"
    assert "abuseipdb" in intel, "threat_intel must include abuseipdb"
    assert "urlscan" in intel, "threat_intel must include urlscan"
    assert "google_safe_browsing" in intel, "threat_intel must include google_safe_browsing"
    assert "geoip" in intel, "threat_intel must include geoip"
    assert "mode" in intel, "threat_intel must declare mode"
    assert "fallback_used" in intel, "threat_intel must declare fallback_used"
    assert "provider_statuses" in intel, "threat_intel must declare provider_statuses"

    # IOCs contract
    assert "iocs" in data, "Response must include 'iocs'"
    assert isinstance(data["iocs"], list)
    for ioc in data["iocs"]:
        assert "type" in ioc, "IOC must have 'type'"
        assert "value" in ioc, "IOC must have 'value'"
        assert "malicious" in ioc, "IOC must have 'malicious'"

