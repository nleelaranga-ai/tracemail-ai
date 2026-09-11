"""
Unit tests for Campaign Correlation Engine and Endpoints (SIH26106)
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_list_campaigns_endpoint():
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    
    # Verify campaign schema
    first_cmp = data[0]
    assert "id" in first_cmp
    assert "name" in first_cmp
    assert "target_brand" in first_cmp
    assert "threat_actor" in first_cmp
    assert "verdict" in first_cmp
    assert "risk_level" in first_cmp
    assert "total_emails" in first_cmp
    assert "playbook" in first_cmp
    assert isinstance(first_cmp["playbook"], list)


def test_get_campaign_detail():
    # Fetch list first
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    
    cmp_id = data[0]["id"]
    detail_res = client.get(f"/api/campaigns/{cmp_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == cmp_id
    assert "investigations" in detail
    assert "timeline" in detail
    assert isinstance(detail["timeline"], list)


def test_campaign_not_found():
    res = client.get("/api/campaigns/non-existent-campaign-id")
    assert res.status_code == 404
