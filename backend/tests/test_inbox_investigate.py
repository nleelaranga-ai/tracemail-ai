"""
Unit & Integration tests for On-Demand Mailbox Message Investigation & MTA Trust Boundary:
- Real raw MIME Gmail extraction vs demo fallback elimination
- Idempotency & concurrency locking
- Spoof-resistant Trusted MTA boundary IP resolution
- IDOR mailbox ownership verification
- Size guard limits
"""
import uuid
import base64
import asyncio
import pytest
import httpx
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta

from backend.main import app
from backend.database.connection import SessionLocal
from backend.models.v2_models import GmailAccount, InboxScanResult
from backend.models.scan import Investigation
from backend.models.user import User
from backend.services.inbox_service import InboxService
from backend.parsers.header_parser import HeaderParser

client = TestClient(app)


SAMPLE_UNSTOP_EML = b"""From: Tanu Goel <noreply@unstop.news>
To: analyst@tracemail.ai
Subject: Everything you need before your next application
Date: Sun, 13 Sep 2026 12:00:00 +0000
Message-ID: <unstop-msg-999@unstop.news>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received: from mail.unstop.news (mail.unstop.news [104.30.10.15]) by mx.google.com with ESMTPS id abc123xyz for <analyst@tracemail.ai>; Sun, 13 Sep 2026 12:00:01 +0000

Hello Candidate,

Everything you need before your next application is ready on Unstop.
Practice coding challenges, submit hackathons, and discover internships.

Best regards,
Unstop Team
"""


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_trusted_mta_boundary_rejects_attacker_forged_received_header():
    """
    RC-8 Verification:
    An attacker sends an email injecting fake Received headers claiming
    to be from an innocent server (1.2.3.4). The email enters Google's MX
    from the actual sender IP (198.51.100.55).
    The MTA trust boundary MUST extract 198.51.100.55, NOT 1.2.3.4.
    """
    forged_headers = (
        "Received: by mail-wm1-f41.google.com with SMTP id ... for <victim@gmail.com>; Sun, 13 Sep 2026 12:00:02 +0000\n"
        "Received: from attacker.relay.net (attacker.relay.net [198.51.100.55]) by mx.google.com with ESMTPS id g123; Sun, 13 Sep 2026 12:00:01 +0000\n"
        "Received: from forged-victim.bank.com (forged-victim.bank.com [1.2.3.4]) by attacker.relay.net with ESMTP id f999; Sun, 13 Sep 2026 11:59:59 +0000\n"
        "From: Attacker <alert@paypal-update.com>\n"
        "To: Victim <victim@gmail.com>\n"
        "Subject: Fake alert\n"
    )

    extracted_ip = HeaderParser.extract_originating_ip(forged_headers)
    assert extracted_ip == "198.51.100.55", (
        f"Expected trusted gateway IP 198.51.100.55, but got forged IP {extracted_ip}"
    )


def test_investigate_message_demo_mapping(db_session):
    """Verifies demo messages correctly resolve to benchmark cases in demo mode."""
    account_email = f"demo_analyst_{uuid.uuid4().hex[:6]}@tracemail.ai"
    InboxService.connect_account(account_email, db_session)
    client.post(f"/api/inbox/scan?email={account_email}")

    res = client.post(f"/api/inbox/messages/msg_gmail_98231/investigate?email={account_email}")
    assert res.status_code == 200
    data = res.json()
    assert data["messageId"] == "msg_gmail_98231"
    assert data["investigationId"] == "inv_paypal_phish_demo_01"


def test_investigate_message_real_live_eml(db_session):
    """
    RC-1 & RC-2 Verification:
    Tests that investigating a real scanned email (Unstop) fetches raw MIME from Gmail,
    decodes it, runs full forensic analysis, and generates a real Investigation record
    (NOT inv_internshala_demo_02).
    """
    uid = uuid.uuid4().hex[:6]
    account_email = f"live_user_{uid}@gmail.com"
    msg_id = f"msg_live_unstop_{uid}"

    account = GmailAccount(
        email=account_email,
        access_token="ya29.a0AfH6_live_token_for_test",
        refresh_token="1//04_refresh_token_test",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        connected=True
    )
    db_session.add(account)

    scan_row = InboxScanResult(
        account_email=account_email,
        message_id=msg_id,
        investigation_id="",  # Empty, needs on-demand investigation!
        sender="Tanu Goel <noreply@unstop.news>",
        subject="Everything you need before your next application",
        snippet="Everything you need before your next application is ready on Unstop.",
        risk="Safe",
        threat_score=10,
        verdict="safe",
        scanned_at=datetime.now(timezone.utc)
    )
    db_session.add(scan_row)
    db_session.commit()

    raw_b64 = base64.urlsafe_b64encode(SAMPLE_UNSTOP_EML).decode("ascii")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": msg_id,
        "raw": raw_b64
    }
    mock_response.raise_for_status = lambda: None

    with patch.object(InboxService, "is_oauth_configured", return_value=True), \
         patch("httpx.AsyncClient.get", return_value=mock_response):

        res = client.post(f"/api/inbox/messages/{msg_id}/investigate?email={account_email}")
        assert res.status_code == 200, f"Error: {res.text}"
        data = res.json()

        assert data["messageId"] == msg_id
        assert data["investigationId"] != "inv_internshala_demo_02", (
            "CRITICAL BUG: Still returned seeded demo ID inv_internshala_demo_02!"
        )
        assert data["investigationId"] != "inv_paypal_phish_demo_01"
        assert data["mode"] == "live"
        assert "unstop.news" in data["sender"]
        assert "Everything you need" in data["subject"]

        db_session.expire_all()
        updated_scan = db_session.query(InboxScanResult).filter(
            InboxScanResult.account_email == account_email,
            InboxScanResult.message_id == msg_id
        ).first()
        assert updated_scan is not None
        assert updated_scan.investigation_id == data["investigationId"]

        inv = db_session.query(Investigation).filter(
            Investigation.id == data["investigationId"]
        ).first()
        assert inv is not None
        assert "unstop.news" in inv.sender
        assert "Everything you need" in inv.subject
        assert inv.ip == "104.30.10.15"

        # Idempotency check: call second time
        res2 = client.post(f"/api/inbox/messages/{msg_id}/investigate?email={account_email}")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["mode"] == "existing"
        assert data2["investigationId"] == data["investigationId"]


@pytest.mark.asyncio
async def test_investigate_message_concurrency():
    """
    Tests that two concurrent requests for the same message ID both complete safely,
    relying on row-level locking, and return identical investigation IDs.
    """
    uid = uuid.uuid4().hex[:6]
    account_email = f"concurrent_user_{uid}@gmail.com"
    msg_id = f"msg_concurrent_{uid}"

    db = SessionLocal()
    try:
        account = GmailAccount(
            email=account_email,
            access_token="ya29.concurrent_live_token",
            refresh_token="1//concurrent_refresh",
            token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
            connected=True
        )
        db.add(account)
        scan_row = InboxScanResult(
            account_email=account_email,
            message_id=msg_id,
            investigation_id="",
            sender="Alert <system@test.org>",
            subject="Concurrent Processing Test",
            snippet="Testing concurrency",
            risk="Safe",
            threat_score=5,
            verdict="safe",
            scanned_at=datetime.now(timezone.utc)
        )
        db.add(scan_row)
        db.commit()
    finally:
        db.close()

    raw_b64 = base64.urlsafe_b64encode(SAMPLE_UNSTOP_EML).decode("ascii")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": msg_id, "raw": raw_b64}
    mock_resp.raise_for_status = lambda: None

    async def call_investigate():
        session = SessionLocal()
        try:
            return await InboxService.investigate_message(
                account_email=account_email,
                message_id=msg_id,
                db=session,
                current_user=None
            )
        finally:
            session.close()

    with patch.object(InboxService, "is_oauth_configured", return_value=True), \
         patch("httpx.AsyncClient.get", return_value=mock_resp):

        res1, res2 = await asyncio.gather(call_investigate(), call_investigate())

        assert res1["investigationId"] == res2["investigationId"]
        assert res1["investigationId"] != ""


@pytest.mark.asyncio
async def test_investigate_message_concurrent_http_requests():
    """
    RC-2 Concurrency & Idempotency Verification:
    Fires 2 simultaneous HTTP POST requests to /api/inbox/messages/{msg_id}/investigate
    via asyncio.gather over ASGI transport. Both must return 200 OK with identical
    investigation IDs, and exactly 1 investigation record must be created in the database.
    """
    uid = uuid.uuid4().hex[:6]
    account_email = f"concurrent_http_{uid}@gmail.com"
    msg_id = f"msg_http_conc_{uid}"

    db = SessionLocal()
    try:
        account = GmailAccount(
            email=account_email,
            access_token="ya29.concurrent_http_token",
            refresh_token="1//concurrent_http_refresh",
            token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
            connected=True
        )
        db.add(account)
        scan_row = InboxScanResult(
            account_email=account_email,
            message_id=msg_id,
            investigation_id="",
            sender="Alert <alert@concurrent-test.org>",
            subject="Simultaneous HTTP Request Test",
            snippet="Testing concurrent HTTP requests",
            risk="Safe",
            threat_score=10,
            verdict="safe",
            scanned_at=datetime.now(timezone.utc)
        )
        db.add(scan_row)
        db.commit()
    finally:
        db.close()

    raw_b64 = base64.urlsafe_b64encode(SAMPLE_UNSTOP_EML).decode("ascii")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": msg_id, "raw": raw_b64}
    mock_resp.raise_for_status = lambda: None

    with patch.object(InboxService, "is_oauth_configured", return_value=True), \
         patch("httpx.AsyncClient.get", return_value=mock_resp):

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as ac:
            req1 = ac.post(f"/api/inbox/messages/{msg_id}/investigate?email={account_email}")
            req2 = ac.post(f"/api/inbox/messages/{msg_id}/investigate?email={account_email}")
            res1, res2 = await asyncio.gather(req1, req2)

        assert res1.status_code == 200, f"Req 1 failed: {res1.text}"
        assert res2.status_code == 200, f"Req 2 failed: {res2.text}"

        d1 = res1.json()
        d2 = res2.json()
        assert d1["investigationId"] == d2["investigationId"]
        assert d1["investigationId"] != ""

        db_check = SessionLocal()
        try:
            count = db_check.query(Investigation).filter(Investigation.id == d1["investigationId"]).count()
            assert count == 1, f"Expected exactly 1 investigation in DB, found {count}"
        finally:
            db_check.close()


def test_investigate_message_size_guard(db_session):
    """Verifies that payloads exceeding 25MB are rejected with 413 Payload Too Large."""
    uid = uuid.uuid4().hex[:6]
    account_email = f"size_test_{uid}@gmail.com"
    msg_id = f"msg_oversized_{uid}"

    account = GmailAccount(
        email=account_email,
        access_token="ya29.size_test_token",
        refresh_token="1//size_test",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        connected=True
    )
    db_session.add(account)
    scan_row = InboxScanResult(
        account_email=account_email,
        message_id=msg_id,
        investigation_id="",
        sender="Large Sender <big@oversized.com>",
        subject="Big Attachment",
        snippet="Huge email",
        risk="Suspicious",
        threat_score=50,
        verdict="suspicious",
        scanned_at=datetime.now(timezone.utc)
    )
    db_session.add(scan_row)
    db_session.commit()

    large_bytes = b"A" * (26 * 1024 * 1024)
    raw_b64 = base64.urlsafe_b64encode(large_bytes).decode("ascii")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": msg_id, "raw": raw_b64}
    mock_resp.raise_for_status = lambda: None

    with patch.object(InboxService, "is_oauth_configured", return_value=True), \
         patch("httpx.AsyncClient.get", return_value=mock_resp):

        res = client.post(f"/api/inbox/messages/{msg_id}/investigate?email={account_email}")
        assert res.status_code == 413
        assert "exceeds 25MB" in res.text


def test_investigate_message_idor_protection(db_session):
    """
    Verifies that a user cannot investigate an account owned by a different user.
    """
    uid1 = uuid.uuid4().hex[:6]
    uid2 = uuid.uuid4().hex[:6]
    owner = User(
        id=f"usr_owner_{uid1}",
        email=f"owner_{uid1}@target.org",
        hashed_password="pw",
        name="Owner",
        role="analyst"
    )
    attacker = User(
        id=f"usr_attacker_{uid2}",
        email=f"attacker_{uid2}@external.org",
        hashed_password="pw",
        name="Attacker",
        role="analyst"
    )
    db_session.add_all([owner, attacker])
    db_session.commit()

    account = GmailAccount(
        email=f"secret_mailbox_{uid1}@target.org",
        owner_user_id=owner.id,
        access_token="ya29.secret_token",
        refresh_token="1//secret",
        token_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        connected=True
    )
    scan_row = InboxScanResult(
        account_email=account.email,
        message_id=f"msg_secret_{uid1}",
        investigation_id="",
        sender="CEO <ceo@target.org>",
        subject="Confidential",
        snippet="Secret",
        risk="Safe",
        threat_score=10,
        verdict="safe",
        scanned_at=datetime.now(timezone.utc)
    )
    db_session.add_all([account, scan_row])
    db_session.commit()

    with pytest.raises(Exception) as excinfo:
        asyncio.run(
            InboxService.investigate_message(
                account_email=account.email,
                message_id=f"msg_secret_{uid1}",
                db=db_session,
                current_user=attacker
            )
        )
    assert "404" in str(excinfo.value)
