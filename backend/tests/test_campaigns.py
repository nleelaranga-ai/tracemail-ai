"""
Unit tests for Campaign Correlation Engine and Endpoints (SIH26106)
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.auth_service import AuthService

client = TestClient(app)


@pytest.fixture
def auth_headers():
    token = AuthService.create_access_token({"sub": "analyst@tracemail.ai", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def test_list_campaigns_endpoint(auth_headers):
    res = client.get("/api/campaigns", headers=auth_headers)
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


def test_get_campaign_detail(auth_headers):
    # Fetch list first
    res = client.get("/api/campaigns", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    
    cmp_id = data[0]["id"]
    detail_res = client.get(f"/api/campaigns/{cmp_id}", headers=auth_headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == cmp_id
    assert "investigations" in detail
    assert "timeline" in detail
    assert isinstance(detail["timeline"], list)


def test_campaign_not_found(auth_headers):
    res = client.get("/api/campaigns/non-existent-campaign-id", headers=auth_headers)
    assert res.status_code == 404
