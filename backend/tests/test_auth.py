"""
Unit tests for Backend User Authentication and JWT
"""
import uuid
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_user_registration_and_login():
    unique_email = f"analyst_{uuid.uuid4().hex[:8]}@cybercell.gov.in"
    password = "SuperSecretPassword123!"

    # 1. Register
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"email": unique_email, "password": password, "name": "Forensic Officer"}
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert "token" in reg_data
    assert reg_data["user"]["email"] == unique_email

    # 2. Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": password}
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    assert len(token) > 20

    # 3. Authenticated me endpoint
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    assert me_res.json()["email"] == unique_email


def test_login_invalid_password():
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@target.org", "password": "WrongPassword999!"}
    )
    assert res.status_code == 401
