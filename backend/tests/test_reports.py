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
