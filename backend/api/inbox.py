"""
TraceMail AI Backend — Live Gmail OAuth & Inbox Scanner Router
"""
import os
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from starlette.responses import RedirectResponse
from backend.database.connection import get_db, Session
from backend.services.inbox_service import InboxService

from backend.models.user import User
from backend.middleware.auth import get_current_user

router = APIRouter(tags=["Gmail Inbox Scanner"])


@router.get("/api/auth/google/login")
def google_oauth_login(origin: Optional[str] = Query(None, description="Frontend origin URL for state redirect")):
    """Generates and redirects to Google OAuth consent screen."""
    url = InboxService.get_google_auth_url(state=origin)
    return {
        "authUrl": url,
        "provider": "Google Identity (OAuth 2.0)",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "configured": InboxService.is_oauth_configured()
    }


@router.get("/api/auth/google/callback")
async def google_oauth_callback(
    code: Optional[str] = Query(None, description="Google OAuth authorization code"),
    state: Optional[str] = Query(None, description="Frontend origin state returned by Google"),
    email: Optional[str] = Query(None, description="Direct email for test/fallback registration"),
    redirect_to_frontend: Optional[bool] = Query(True, description="Redirect browser to frontend after exchange"),
    db: Session = Depends(get_db)
):
    """Exchanges Google auth code for live tokens or registers connected inbox."""
    import os
    import urllib.parse
    target_frontend = os.getenv("FRONTEND_URL", "https://tracemail-ai-84ho.vercel.app").rstrip("/")
    if state and state.startswith("http"):
        target_frontend = state.rstrip("/")

    if code:
        res = await InboxService.exchange_code_and_connect(code, db)
        if redirect_to_frontend:
            connected_email = res.get("email", "connected")
            mode = res.get("mode", "live")
            err_msg = res.get("error", "")
            err_q = f"&error={urllib.parse.quote(err_msg)}" if err_msg else ""
            is_conn = "true" if res.get("connected") else "false"
            return RedirectResponse(url=f"{target_frontend}/inbox?connected={is_conn}&email={connected_email}&mode={mode}{err_q}")
        return res
    target_email = email or "analyst@tracemail.ai"
    return InboxService.connect_account(target_email, db)


@router.get("/api/auth/google/status")
def get_google_status(
    email: Optional[str] = Query(None, description="Account email to check"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns current connection status and provider configuration."""
    return InboxService.get_connection_status(email, db, current_user=current_user)


@router.post("/api/auth/google/disconnect")
def disconnect_google_inbox(
    email: Optional[str] = Query(None, description="Account email to disconnect"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Disconnects monitored mailbox."""
    return InboxService.disconnect_account(email, db, current_user=current_user)


@router.post("/api/inbox/scan")
async def trigger_inbox_scan(
    email: Optional[str] = Query(None, description="Monitored account email"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Triggers background mailbox scan and evaluates incoming email threat levels."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to trigger inbox scan.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    target_email = email or current_user.email

    # Router-level gate: strictly prohibit unconfigured demo scanning in production
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env in ("production", "prod"):
        if not InboxService.is_oauth_configured():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Google Workspace OAuth is not configured on this production instance."
            )
        if target_email in ("analyst@tracemail.ai", "soc-analyst@tracemail.ai") and getattr(current_user, "role", "") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Demo account simulation is disabled in production."
            )

    return await InboxService.scan_mailbox(target_email, db, current_user=current_user)


@router.get("/api/inbox/results")
def get_inbox_results(
    email: Optional[str] = Query(None, description="Filter results by account email"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Returns past scanned emails from connected inbox with mandatory authentication."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view inbox scan results.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return InboxService.get_inbox_results(email, db, current_user=current_user)


@router.post("/api/inbox/messages/{message_id}/investigate")
async def investigate_mailbox_message(
    message_id: str,
    email: str = Query(..., description="Monitored account email"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Triggers on-demand deep forensic investigation of a specific mailbox message."""
    return await InboxService.investigate_message(
        account_email=email,
        message_id=message_id,
        db=db,
        current_user=current_user
    )
