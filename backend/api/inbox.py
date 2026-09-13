"""
TraceMail AI Backend — Live Gmail OAuth & Inbox Scanner Router
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query
from starlette.responses import RedirectResponse
from backend.database.connection import get_db, Session
from backend.services.inbox_service import InboxService

router = APIRouter(tags=["Gmail Inbox Scanner"])


@router.get("/api/auth/google/login")
def google_oauth_login():
    """Generates and redirects to Google OAuth consent screen."""
    url = InboxService.get_google_auth_url()
    return {
        "authUrl": url,
        "provider": "Google Identity (OAuth 2.0)",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "configured": InboxService.is_oauth_configured()
    }


@router.get("/api/auth/google/callback")
async def google_oauth_callback(
    code: Optional[str] = Query(None, description="Google OAuth authorization code"),
    email: Optional[str] = Query(None, description="Direct email for test/fallback registration"),
    db: Session = Depends(get_db)
):
    """Exchanges Google auth code for live tokens or registers connected inbox."""
    if code:
        return await InboxService.exchange_code_and_connect(code, db)
    target_email = email or "analyst@tracemail.ai"
    return InboxService.connect_account(target_email, db)


@router.get("/api/auth/google/status")
def get_google_status(
    email: Optional[str] = Query(None, description="Account email to check"),
    db: Session = Depends(get_db)
):
    """Returns current connection status and provider configuration."""
    return InboxService.get_connection_status(email, db)


@router.post("/api/auth/google/disconnect")
def disconnect_google_inbox(
    email: Optional[str] = Query(None, description="Account email to disconnect"),
    db: Session = Depends(get_db)
):
    """Disconnects monitored mailbox."""
    return InboxService.disconnect_account(email, db)


@router.post("/api/inbox/scan")
async def trigger_inbox_scan(
    email: Optional[str] = Query("analyst@tracemail.ai", description="Monitored account email"),
    db: Session = Depends(get_db)
):
    """Triggers background mailbox scan and evaluates incoming email threat levels."""
    return await InboxService.scan_mailbox(email, db)


@router.get("/api/inbox/results")
def get_inbox_results(
    email: Optional[str] = Query(None, description="Filter results by account email"),
    db: Session = Depends(get_db)
):
    """Returns past scanned emails from connected inbox."""
    return InboxService.get_inbox_results(email, db)
