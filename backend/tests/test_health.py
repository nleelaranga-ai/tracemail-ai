"""
Unit tests for Backend Health and Documentation Endpoints
"""
try:
    import pytest
except ImportError:
    pass
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "backend-api"
    assert data["status"] in ["healthy", "degraded"]


def test_openapi_docs_available():
    res = client.get("/docs")
    assert res.status_code == 200
    res_json = client.get("/openapi.json")
    assert res_json.status_code == 200
    assert "TraceMail AI" in res_json.json()["info"]["title"]
