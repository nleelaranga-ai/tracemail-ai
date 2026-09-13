"""
Test Suite: Mandatory Authentication and Tenant Isolation Hardening
Verifies that all list, detail, and analytics endpoints enforce default-deny:
- Unauthenticated requests receive 401 Unauthorized
- Non-admin users can never access records owned by another user or unowned records
- Admin users retain global oversight
"""
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.connection import SessionLocal
from backend.models.user import User
from backend.models.scan import Investigation
from backend.models.v2_models import GmailAccount, InboxScanResult
from backend.services.auth_service import AuthService

client = TestClient(app)


@pytest.fixture
def auth_tenants():
    """Sets up two distinct user tenants (User A and User B) plus an Admin user."""
    db = SessionLocal()
    uid = uuid.uuid4().hex[:6]
    email_a = f"tenant_a_{uid}@corp.com"
    email_b = f"tenant_b_{uid}@corp.com"
    email_admin = f"admin_{uid}@corp.com"

    user_a = AuthService.register_user(db, email_a, "Password123!", name="Tenant A")
    user_b = AuthService.register_user(db, email_b, "Password123!", name="Tenant B")
    user_admin = AuthService.register_user(db, email_admin, "Password123!", name="Admin User")
    user_admin.role = "admin"
    db.commit()

    # Seed an investigation owned by User A
    inv_a = Investigation(
        id=f"inv_a_{uid}",
        owner_user_id=user_a.id,
        sender="attacker@phish-a.com",
        recipient=email_a,
        subject="Phish targeting Tenant A",
        received_at=datetime.now(timezone.utc),
        verdict="phishing",
        threat_score=95,
        risk_level="Critical",
        status="complete"
    )
    # Seed an investigation owned by User B
    inv_b = Investigation(
        id=f"inv_b_{uid}",
        owner_user_id=user_b.id,
        sender="attacker@phish-b.com",
        recipient=email_b,
        subject="Phish targeting Tenant B",
        received_at=datetime.now(timezone.utc),
        verdict="phishing",
        threat_score=90,
        risk_level="Critical",
        status="complete"
    )
    # Seed an unowned investigation (null owner)
    inv_null = Investigation(
        id=f"inv_null_{uid}",
        owner_user_id=None,
        sender="unknown@external.com",
        recipient="nobody@corp.com",
        subject="Unowned Legacy Record",
        received_at=datetime.now(timezone.utc),
        verdict="safe",
        threat_score=10,
        risk_level="Low",
        status="complete"
    )
    db.add(inv_a)
    db.add(inv_b)
    db.add(inv_null)
    db.commit()

    token_a = AuthService.create_access_token({"sub": email_a})
    token_b = AuthService.create_access_token({"sub": email_b})
    token_admin = AuthService.create_access_token({"sub": email_admin})

    yield {
        "user_a": user_a,
        "user_b": user_b,
        "user_admin": user_admin,
        "inv_a": inv_a,
        "inv_b": inv_b,
        "inv_null": inv_null,
        "token_a": token_a,
        "token_b": token_b,
        "token_admin": token_admin,
    }

    db.close()


def test_list_investigations_unauthenticated_returns_401():
    """Unauthenticated calls to GET /api/investigations must be rejected with 401."""
    res = client.get("/api/investigations")
    assert res.status_code == 401
    data = res.json()
    assert "Authentication required" in (data.get("message") or data.get("detail", ""))


def test_list_investigations_isolated_to_owner(auth_tenants):
    """User A only sees their own investigations; never User B's or unowned."""
    token_a = auth_tenants["token_a"]
    headers = {"Authorization": f"Bearer {token_a}"}
    res = client.get("/api/investigations", headers=headers)
    assert res.status_code == 200
    ids = [item["id"] for item in res.json()]
    assert auth_tenants["inv_a"].id in ids
    assert auth_tenants["inv_b"].id not in ids
    assert auth_tenants["inv_null"].id not in ids


def test_detail_investigation_isolated_to_owner(auth_tenants):
    """User A cannot access User B's investigation detail or unowned investigation (returns 404)."""
    token_a = auth_tenants["token_a"]
    headers = {"Authorization": f"Bearer {token_a}"}

    # Access own case -> 200
    res_own = client.get(f"/api/investigations/{auth_tenants['inv_a'].id}", headers=headers)
    assert res_own.status_code == 200

    # Cross-tenant access -> 404
    res_other = client.get(f"/api/investigations/{auth_tenants['inv_b'].id}", headers=headers)
    assert res_other.status_code == 404

    # Unowned / null owner case -> 404 (default-deny for non-admin)
    res_null = client.get(f"/api/investigations/{auth_tenants['inv_null'].id}", headers=headers)
    assert res_null.status_code == 404


def test_admin_can_access_all_investigations(auth_tenants):
    """Admin role bypasses tenant boundary and can see all cases including unowned."""
    token_admin = auth_tenants["token_admin"]
    headers = {"Authorization": f"Bearer {token_admin}"}

    res_list = client.get("/api/investigations", headers=headers)
    assert res_list.status_code == 200
    ids = [item["id"] for item in res_list.json()]
    assert auth_tenants["inv_a"].id in ids
    assert auth_tenants["inv_b"].id in ids
    assert auth_tenants["inv_null"].id in ids

    # Admin access to null-owner detail -> 200
    res_null = client.get(f"/api/investigations/{auth_tenants['inv_null'].id}", headers=headers)
    assert res_null.status_code == 200


def test_inbox_results_unauthenticated_returns_401():
    """Unauthenticated calls to GET /api/inbox/results must return 401."""
    res = client.get("/api/inbox/results")
    assert res.status_code == 401


def test_campaigns_unauthenticated_returns_401():
    """Unauthenticated calls to GET /api/campaigns must return 401."""
    res = client.get("/api/campaigns")
    assert res.status_code == 401


def test_evidence_unauthenticated_returns_401():
    """Unauthenticated calls to GET /api/evidence must return 401."""
    res = client.get("/api/evidence")
    assert res.status_code == 401


def test_soc_overview_unauthenticated_returns_401():
    """Unauthenticated calls to GET /api/soc/overview must return 401."""
    res = client.get("/api/soc/overview")
    assert res.status_code == 401
