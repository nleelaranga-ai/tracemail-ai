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
    return {"authUrl": url, "provider": "Google Identity", "scope": "gmail.readonly"}


@router.get("/api/auth/google/callback")
def google_oauth_callback(code: Optional[str] = None, email: Optional[str] = "analyst@tracemail.ai", db: Session = Depends(get_db)):
    """Exchanges Google auth code for tokens and registers connected inbox."""
    res = InboxService.connect_account(email, db)
    return res


@router.post("/api/inbox/scan")
def trigger_inbox_scan(email: Optional[str] = "analyst@tracemail.ai", db: Session = Depends(get_db)):
    """Triggers background mailbox scan and evaluates incoming email threat levels."""
    return InboxService.scan_mailbox(email, db)


@router.get("/api/inbox/results")
def get_inbox_results(email: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns past scanned emails from connected inbox."""
    return InboxService.get_inbox_results(email, db)
