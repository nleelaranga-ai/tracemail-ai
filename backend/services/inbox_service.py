"""
TraceMail AI Backend — Live Gmail OAuth & Inbox Scanner Service
Connects to Google Workspace / Gmail API, scans incoming emails in background,
and feeds messages directly into TraceMail investigation pipeline.
Supports full OAuth 2.0 code exchange, token refresh, and graceful demo fallbacks.
"""
import os
import base64
import asyncio
import httpx
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from backend.database.connection import Session
from backend.models.v2_models import GmailAccount, InboxScanResult
from backend.models.scan import Investigation
from backend.models.user import User
from backend.services.email_service import EmailService
from backend.utils.config import settings
from backend.utils.logger import logger


class TokenRefreshError(Exception):
    """Raised when Gmail OAuth access token cannot be refreshed."""
    pass


class InboxService:
    GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

    @classmethod
    def is_oauth_configured(cls) -> bool:
        """Returns True if Google OAuth Client credentials are provided."""
        return bool(settings.GOOGLE_CLIENT_ID.strip() and settings.GOOGLE_CLIENT_SECRET.strip())

    @classmethod
    def get_google_auth_url(cls, state: Optional[str] = None) -> str:
        """Generates the standard Google OAuth 2.0 authorization URL."""
        client_id = settings.GOOGLE_CLIENT_ID.strip() or "tracemail-sih-google-oauth-client.apps.googleusercontent.com"
        redirect_uri = settings.GOOGLE_REDIRECT_URI.strip() or "http://localhost:3000/inbox"
        scope = "https://www.googleapis.com/auth/gmail.readonly"
        url = (
            f"{cls.GOOGLE_AUTH_ENDPOINT}"
            f"?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
            f"&scope={scope}&access_type=offline&prompt=consent"
        )
        if state:
            import urllib.parse
            url += f"&state={urllib.parse.quote(state)}"
        return url

    @classmethod
    async def exchange_code_and_connect(cls, code: str, db: Session, owner_user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchanges Google authorization code for access and refresh tokens.
        Fetches the user profile and registers the connected GmailAccount.
        """
        now = datetime.now(timezone.utc)
        if not cls.is_oauth_configured():
            logger.info("Google OAuth credentials not configured; registering account in simulated mode.")
            return cls.connect_account("analyst@tracemail.ai", db, owner_user_id=owner_user_id)

        client_id = settings.GOOGLE_CLIENT_ID.strip()
        client_secret = settings.GOOGLE_CLIENT_SECRET.strip()
        redirect_uri = settings.GOOGLE_REDIRECT_URI.strip() or "http://localhost:3000/inbox"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                token_resp = await client.post(
                    cls.GOOGLE_TOKEN_ENDPOINT,
                    data={
                        "code": code,
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "redirect_uri": redirect_uri,
                        "grant_type": "authorization_code"
                    }
                )

                if token_resp.status_code != 200:
                    logger.warning(f"Google token exchange returned status {token_resp.status_code}: {token_resp.text}")
                    return {
                        "connected": False,
                        "email": "",
                        "mode": "error",
                        "error": f"Google authorization rejected (HTTP {token_resp.status_code})"
                    }

                token_data = token_resp.json()
                access_token = token_data.get("access_token", "")
                refresh_token = token_data.get("refresh_token", "")
                expires_in = token_data.get("expires_in", 3600)

                # Fetch user profile to identify connected email address
                profile_resp = await client.get(
                    f"{cls.GMAIL_API_BASE}/profile",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                user_email = "connected-user@gmail.com"
                if profile_resp.status_code == 200:
                    profile_data = profile_resp.json()
                    user_email = profile_data.get("emailAddress", user_email)

                clean_email = user_email.strip().lower()

                # If owner_user_id was not explicitly passed, find matching registered user by email
                if not owner_user_id and clean_email:
                    matched_user = db.query(User).filter(func.lower(User.email) == clean_email).first()
                    if matched_user:
                        owner_user_id = matched_user.id

                # Upsert into database
                existing = db.query(GmailAccount).filter(func.lower(GmailAccount.email) == clean_email).first()
                if not existing:
                    account = GmailAccount(
                        email=clean_email,
                        owner_user_id=owner_user_id,
                        access_token=access_token,
                        refresh_token=refresh_token,
                        token_expiry=now + timedelta(seconds=expires_in),
                        connected=True,
                        created_at=now,
                        last_scanned_at=now
                    )
                    db.add(account)
                else:
                    existing.access_token = access_token
                    if refresh_token:
                        existing.refresh_token = refresh_token
                    existing.token_expiry = now + timedelta(seconds=expires_in)
                    existing.connected = True
                    if owner_user_id:
                        existing.owner_user_id = owner_user_id
                    existing.last_scanned_at = now

                db.commit()
                return {
                    "connected": True,
                    "email": user_email,
                    "provider": "Google Workspace / Gmail API",
                    "live_oauth": True,
                    "mode": "live"
                }

        except Exception as e:
            logger.error(f"Error during Google OAuth code exchange: {e}")
            return {
                "connected": False,
                "email": "",
                "mode": "error",
                "error": str(e)
            }

    @classmethod
    def connect_account(cls, email: str, db: Session, owner_user_id: Optional[str] = None) -> Dict[str, Any]:
        """Registers a connected account (live or demo)."""
        clean_email = (email or "").strip().lower()
        if not owner_user_id and clean_email:
            matched_user = db.query(User).filter(func.lower(User.email) == clean_email).first()
            if matched_user:
                owner_user_id = matched_user.id

        existing = db.query(GmailAccount).filter(func.lower(GmailAccount.email) == clean_email).first()
        now = datetime.now(timezone.utc)
        is_live = cls.is_oauth_configured()
        if not existing:
            account = GmailAccount(
                email=clean_email,
                owner_user_id=owner_user_id,
                access_token="ya29.live-token-active-oauth2" if is_live else "ya29.demo-token-active-oauth2",
                refresh_token="1//0live-refresh-token" if is_live else "1//0demo-refresh-token",
                token_expiry=now + timedelta(days=30),
                connected=True,
                created_at=now,
                last_scanned_at=now
            )
            db.add(account)
        else:
            if owner_user_id:
                existing.owner_user_id = owner_user_id
            existing.connected = True
            existing.last_scanned_at = now

        db.commit()
        return {
            "connected": True,
            "email": email,
            "provider": "Gmail API (OAuth 2.0)",
            "live_oauth": is_live,
            "mode": "live" if is_live else "demo"
        }

    @classmethod
    def disconnect_account(cls, email: Optional[str], db: Session, current_user: Optional[User] = None) -> Dict[str, Any]:
        """Disconnects account from active monitoring with tenant isolation."""
        query = db.query(GmailAccount)
        if email:
            query = query.filter(GmailAccount.email == email)
        if current_user and getattr(current_user, "role", "") != "admin":
            query = query.filter(
                (GmailAccount.owner_user_id == current_user.id) |
                (GmailAccount.email == current_user.email)
            )
        accounts = query.all()
        for a in accounts:
            a.connected = False
        db.commit()
        return {"connected": False, "disconnected": len(accounts)}

    @classmethod
    def get_connection_status(cls, email: Optional[str], db: Session, current_user: Optional[User] = None) -> Dict[str, Any]:
        """Returns current live connection status and configuration state with strict tenant isolation, delegating to canonical verify_mailbox_access."""
        is_configured = cls.is_oauth_configured()
        if not current_user:
            return {
                "connected": False,
                "email": "",
                "mode": "disconnected",
                "client_configured": is_configured,
                "last_scanned_at": None
            }

        try:
            account = cls.verify_mailbox_access(email, current_user, db)
            is_live_token = not account.access_token.startswith("ya29.demo-")
            return {
                "connected": True,
                "email": account.email,
                "mode": "live" if is_live_token and is_configured else "demo",
                "client_configured": is_configured,
                "last_scanned_at": account.last_scanned_at.isoformat() if account.last_scanned_at else None
            }
        except HTTPException:
            return {
                "connected": False,
                "email": "",
                "mode": "disconnected",
                "client_configured": is_configured,
                "last_scanned_at": None
            }

    @classmethod
    def verify_mailbox_access(
        cls,
        account_email: Optional[str],
        current_user: Optional[User],
        db: Session
    ) -> GmailAccount:
        """
        Single canonical ownership check for all mailbox endpoints (scan, results, investigate).
        Enforces tenant isolation:
        - Rejects unauthenticated calls with 401.
        - Admins have global access to all mailboxes.
        - Non-admins must be the legitimate owner:
            * Matches by owner_user_id == current_user.id, OR
            * Matches by normalized email (func.lower(GmailAccount.email) == current_user.email.lower()).
        - If an unlinked account matches the user's email, automatically links owner_user_id.
        - Rejects non-owners / strangers with 403 Forbidden.
        - Rejects non-existent mailboxes with 404 Not Found.
        """
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to access mailbox.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if account_email and account_email.strip():
            target_email = account_email.strip().lower()
            account = db.query(GmailAccount).filter(
                func.lower(GmailAccount.email) == target_email,
                GmailAccount.connected == True
            ).first()
        else:
            # When email is omitted, resolve by current_user's linked mailbox or login email
            account = db.query(GmailAccount).filter(
                (GmailAccount.owner_user_id == current_user.id) |
                (func.lower(GmailAccount.email) == current_user.email.strip().lower()),
                GmailAccount.connected == True
            ).order_by(GmailAccount.last_scanned_at.desc()).first()

        if not account:
            err_msg = f"Connected mailbox '{account_email}' not found." if account_email else "No connected mailbox found for this account."
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg
            )

        # Admin bypass
        if getattr(current_user, "role", "") == "admin":
            return account

        # Strict ownership verification
        is_owner_by_id = (account.owner_user_id is not None) and (account.owner_user_id == current_user.id)
        is_owner_by_email = (account.email.strip().lower() == current_user.email.strip().lower())

        if not (is_owner_by_id or is_owner_by_email):
            logger.warning(
                f"Tenant boundary violation: User {current_user.email} (id={current_user.id}) "
                f"attempted to access mailbox {account.email} (owner_user_id={account.owner_user_id})"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view or scan messages for this mailbox."
            )

        # Self-healing: if owner_user_id was unlinked but emails match, link it permanently
        if account.owner_user_id is None:
            account.owner_user_id = current_user.id
            db.commit()

        return account

    @classmethod
    async def scan_mailbox(cls, account_email: str, db: Session, current_user: Optional[User] = None) -> Dict[str, Any]:
        """
        Scans connected Gmail inbox.
        If live credentials and tokens are present, queries real Gmail API messages.
        Gated demo fallback: Live accounts NEVER silently fall back to mock corpus.
        """
        now = datetime.now(timezone.utc)
        account = cls.verify_mailbox_access(account_email, current_user, db)

        # Try real Gmail API if live access token is available
        if cls.is_oauth_configured() and not account.access_token.startswith("ya29.demo-"):
            try:
                live_results = await cls._fetch_and_scan_real_gmail(account, db)
                if live_results is not None:
                    account.last_scanned_at = now
                    db.commit()
                    return {
                        "jobId": f"job_{int(now.timestamp())}",
                        "status": "complete",
                        "account": account_email,
                        "emailsScanned": len(live_results),
                        "threatsFound": sum(1 for m in live_results if m["verdict"] == "phishing"),
                        "completedAt": now.isoformat(),
                        "mode": "live",
                        "provider": "Google Workspace / Gmail API"
                    }
                else:
                    raise HTTPException(
                        status_code=502,
                        detail="Failed to retrieve messages from Google Workspace Gmail API. Ensure token is valid."
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Live Gmail API scan error: {e}")
                raise HTTPException(
                    status_code=502,
                    detail=f"Live Gmail API scan encountered an error: {str(e)}"
                )

        # Fallback to standard forensic evaluation corpus ONLY for explicit demo simulation in development
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env in ("production", "prod"):
            raise HTTPException(
                status_code=400,
                detail="Demo mailbox accounts are not permitted in production. Please connect a live Google Workspace / Gmail account."
            )

        if not account.access_token.startswith("ya29.demo-"):
            raise HTTPException(
                status_code=400,
                detail="Live Gmail account scan failed and demo fallback is disabled for non-demo accounts."
            )

        # Fallback to standard forensic evaluation corpus (honest on-demand investigation required)
        sample_messages = [
            {
                "message_id": "msg_gmail_98231",
                "investigation_id": "",
                "sender": "Security Team <alert@paypal-update-auth.com>",
                "subject": "ACTION REQUIRED: Account Suspension Notice",
                "snippet": "We detected unauthorized attempts to access your wallet. Confirm your PIN immediately.",
                "risk": "Critical",
                "threat_score": 94,
                "verdict": "phishing"
            },
            {
                "message_id": "msg_gmail_98232",
                "investigation_id": "",
                "sender": "David Miller <ceo@corporate-wire-transfer.com>",
                "subject": "Confidential: Acquisition Wire Instruction",
                "snippet": "Please release the escrow wire of $45,000 today. Keep this strictly under NDA.",
                "risk": "Critical",
                "threat_score": 89,
                "verdict": "phishing"
            },
            {
                "message_id": "msg_gmail_98233",
                "investigation_id": "",
                "sender": "Internshala Student Desk <student-success@internshala.com>",
                "subject": "Your application was shortlisted by Top Employer",
                "snippet": "Congratulations! The hiring team has scheduled an interview for your profile.",
                "risk": "Safe",
                "threat_score": 8,
                "verdict": "safe"
            },
            {
                "message_id": "msg_gmail_98234",
                "investigation_id": "",
                "sender": "Google Cloud Platform <cloud-notifications@google.com>",
                "subject": "Cloud Console: Billing Budget 80% Threshold Reached",
                "snippet": "Your project tracemail-prod has consumed 80% of the allocated $100 monthly budget.",
                "risk": "Safe",
                "threat_score": 14,
                "verdict": "safe"
            }
        ]

        for sm in sample_messages:
            existing = db.query(InboxScanResult).filter(
                InboxScanResult.account_email == account_email,
                InboxScanResult.message_id == sm["message_id"]
            ).first()

            if not existing:
                res = InboxScanResult(
                    account_email=account_email,
                    message_id=sm["message_id"],
                    investigation_id=sm.get("investigation_id", ""),
                    sender=sm["sender"],
                    subject=sm["subject"],
                    snippet=sm["snippet"],
                    risk=sm["risk"],
                    threat_score=sm["threat_score"],
                    verdict=sm["verdict"],
                    scanned_at=now
                )
                db.add(res)
            elif not existing.investigation_id and sm.get("investigation_id"):
                existing.investigation_id = sm.get("investigation_id")

        if account:
            account.last_scanned_at = now

        db.commit()
        return {
            "jobId": f"job_{int(now.timestamp())}",
            "status": "complete",
            "account": account_email,
            "emailsScanned": len(sample_messages),
            "threatsFound": sum(1 for m in sample_messages if m["verdict"] == "phishing"),
            "completedAt": now.isoformat(),
            "mode": "demo",
            "provider": "Gmail Demo Scanner"
        }

    @classmethod
    async def _fetch_and_scan_real_gmail(cls, account: GmailAccount, db: Session) -> Optional[List[Dict[str, Any]]]:
        """Fetches latest real messages from Gmail REST API."""
        now = datetime.now(timezone.utc)
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {account.access_token}"}
            list_resp = await client.get(f"{cls.GMAIL_API_BASE}/messages?maxResults=10&q=in:inbox", headers=headers)

            if list_resp.status_code == 401 and account.refresh_token:
                # Attempt token refresh
                refresh_resp = await client.post(
                    cls.GOOGLE_TOKEN_ENDPOINT,
                    data={
                        "client_id": settings.GOOGLE_CLIENT_ID,
                        "client_secret": settings.GOOGLE_CLIENT_SECRET,
                        "refresh_token": account.refresh_token,
                        "grant_type": "refresh_token"
                    }
                )
                if refresh_resp.status_code == 200:
                    new_token = refresh_resp.json().get("access_token")
                    account.access_token = new_token
                    db.commit()
                    headers["Authorization"] = f"Bearer {new_token}"
                    list_resp = await client.get(f"{cls.GMAIL_API_BASE}/messages?maxResults=10&q=in:inbox", headers=headers)

            if list_resp.status_code != 200:
                return None

            messages_meta = list_resp.json().get("messages", [])
            evaluated_items = []

            for m in messages_meta[:8]:
                msg_id = m["id"]
                msg_resp = await client.get(f"{cls.GMAIL_API_BASE}/messages/{msg_id}?format=full", headers=headers)
                if msg_resp.status_code != 200:
                    continue

                msg_data = msg_resp.json()
                headers_list = msg_data.get("payload", {}).get("headers", [])
                header_map = {h["name"].lower(): h["value"] for h in headers_list if "name" in h and "value" in h}

                sender = header_map.get("from", "Unknown Sender")
                subject = header_map.get("subject", "No Subject")
                snippet = msg_data.get("snippet", "")

                # Quick threat evaluation heuristics
                is_suspicious_sender = any(k in sender.lower() for k in ["alert", "security", "update", "verify", "pay", "bank", "invoice"])
                is_suspicious_subject = any(k in subject.lower() for k in ["urgent", "action required", "suspended", "wire", "password", "shortlisted"])

                threat_score = 15
                if is_suspicious_sender and is_suspicious_subject:
                    threat_score = 88
                    risk = "Critical"
                    verdict = "phishing"
                elif is_suspicious_sender or is_suspicious_subject:
                    threat_score = 62
                    risk = "Suspicious"
                    verdict = "suspicious"
                else:
                    risk = "Safe"
                    verdict = "safe"

                existing = db.query(InboxScanResult).filter(
                    InboxScanResult.account_email == account.email,
                    InboxScanResult.message_id == msg_id
                ).first()

                if not existing:
                    new_res = InboxScanResult(
                        account_email=account.email,
                        message_id=msg_id,
                        investigation_id="",
                        sender=str(sender or "")[:255],
                        subject=str(subject or "")[:500],
                        snippet=snippet,
                        risk=risk,
                        threat_score=threat_score,
                        verdict=verdict,
                        scanned_at=now
                    )
                    db.add(new_res)

                evaluated_items.append({
                    "message_id": msg_id,
                    "sender": sender,
                    "subject": subject,
                    "risk": risk,
                    "threat_score": threat_score,
                    "verdict": verdict
                })

            db.commit()
            return evaluated_items

    @classmethod
    async def poll_all_connected_mailboxes(cls, db: Session) -> Dict[str, Any]:
        """
        Automated background task runner: Iterates through connected Gmail accounts
        and scans new incoming messages every 3 minutes.
        """
        now = datetime.now(timezone.utc)
        accounts = db.query(GmailAccount).filter(GmailAccount.connected == True).all()
        synced_count = 0
        for account in accounts:
            try:
                if cls.is_oauth_configured() and not account.access_token.startswith("ya29.demo-"):
                    await cls._fetch_and_scan_real_gmail(account, db)
                account.last_scanned_at = now
                db.commit()
                synced_count += 1
            except Exception as e:
                logger.warning(f"Background mailbox poll failed for {account.email}: {e}")
                db.rollback()
        return {"polled_accounts": synced_count}

    @classmethod
    def get_inbox_results(
        cls,
        account_email: Optional[str],
        db: Session,
        current_user: Optional[User] = None
    ) -> List[Dict[str, Any]]:
        """Returns past evaluated messages with strict tenant isolation and authentication."""
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to view inbox scan results.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if account_email:
            account = cls.verify_mailbox_access(account_email, current_user, db)
            query = db.query(InboxScanResult).filter(
                func.lower(InboxScanResult.account_email) == account.email.strip().lower()
            )
        else:
            query = db.query(InboxScanResult)
            if getattr(current_user, "role", "") != "admin":
                owned = db.query(GmailAccount.email).filter(
                    (GmailAccount.owner_user_id == current_user.id) |
                    (func.lower(GmailAccount.email) == current_user.email.strip().lower())
                ).all()
                allowed = [o[0].strip().lower() for o in owned]
                query = query.filter(func.lower(InboxScanResult.account_email).in_(allowed))

        records = query.order_by(InboxScanResult.scanned_at.desc()).all()

        if not records:
            # In production or when ENABLE_DEMO_SEED=false, never seed demo records
            env = os.getenv("ENVIRONMENT", "development").lower()
            enable_seed = os.getenv("ENABLE_DEMO_SEED", "false" if env in ("production", "prod") else "true").lower() in ("true", "1", "yes")
            if env in ("production", "prod") or not enable_seed or account_email not in (None, "analyst@tracemail.ai", "soc-analyst@tracemail.ai"):
                return []

            # Seed demo records on first load ONLY for local development demo analyst
            cls.connect_account("soc-analyst@tracemail.ai", db)
            # Synchronous sample insertion (requires real on-demand investigation)
            now = datetime.now(timezone.utc)
            samples = [
                {
                    "message_id": "msg_gmail_98231",
                    "investigation_id": "",
                    "sender": "Security Team <alert@paypal-update-auth.com>",
                    "subject": "ACTION REQUIRED: Account Suspension Notice",
                    "snippet": "We detected unauthorized attempts to access your wallet. Confirm your PIN immediately.",
                    "risk": "Critical",
                    "threat_score": 94,
                    "verdict": "phishing"
                },
                {
                    "message_id": "msg_gmail_98232",
                    "investigation_id": "",
                    "sender": "David Miller <ceo@corporate-wire-transfer.com>",
                    "subject": "Confidential: Acquisition Wire Instruction",
                    "snippet": "Please release the escrow wire of $45,000 today. Keep this strictly under NDA.",
                    "risk": "Critical",
                    "threat_score": 89,
                    "verdict": "phishing"
                },
                {
                    "message_id": "msg_gmail_98233",
                    "investigation_id": "",
                    "sender": "Internshala Student Desk <student-success@internshala.com>",
                    "subject": "Your application was shortlisted by Top Employer",
                    "snippet": "Congratulations! The hiring team has scheduled an interview for your profile.",
                    "risk": "Safe",
                    "threat_score": 8,
                    "verdict": "safe"
                },
                {
                    "message_id": "msg_gmail_98234",
                    "investigation_id": "",
                    "sender": "Google Cloud Platform <cloud-notifications@google.com>",
                    "subject": "Cloud Console: Billing Budget 80% Threshold Reached",
                    "snippet": "Your project tracemail-prod has consumed 80% of the allocated $100 monthly budget.",
                    "risk": "Safe",
                    "threat_score": 14,
                    "verdict": "safe"
                }
            ]
            for sm in samples:
                res = InboxScanResult(
                    account_email="soc-analyst@tracemail.ai",
                    message_id=sm["message_id"],
                    investigation_id=sm["investigation_id"],
                    sender=sm["sender"],
                    subject=sm["subject"],
                    snippet=sm["snippet"],
                    risk=sm["risk"],
                    threat_score=sm["threat_score"],
                    verdict=sm["verdict"],
                    scanned_at=now
                )
                db.add(res)
            db.commit()
            records = db.query(InboxScanResult).order_by(InboxScanResult.scanned_at.desc()).all()

        return [
            {
                "id": r.id,
                "messageId": r.message_id,
                "investigationId": r.investigation_id or "",
                "sender": r.sender,
                "subject": r.subject,
                "snippet": r.snippet,
                "risk": r.risk,
                "threatScore": r.threat_score,
                "verdict": r.verdict,
                "scannedAt": r.scanned_at.isoformat() if r.scanned_at else datetime.now(timezone.utc).isoformat()
            }
            for r in records
        ]

    @classmethod
    async def _get_valid_access_token(cls, account: GmailAccount, db: Session) -> str:
        """Ensures the access token is valid and unexpired. Refreshes if needed."""
        now = datetime.now(timezone.utc)
        token_expiry = account.token_expiry
        if token_expiry:
            if token_expiry.tzinfo is None:
                token_expiry = token_expiry.replace(tzinfo=timezone.utc)
            if token_expiry <= now + timedelta(seconds=60):
                if not account.refresh_token:
                    raise TokenRefreshError("Gmail authorization expired and no refresh token available")

                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        cls.GOOGLE_TOKEN_ENDPOINT,
                        data={
                            "client_id": settings.GOOGLE_CLIENT_ID,
                            "client_secret": settings.GOOGLE_CLIENT_SECRET,
                            "refresh_token": account.refresh_token,
                            "grant_type": "refresh_token"
                        }
                    )
                    if resp.status_code != 200:
                        raise TokenRefreshError(f"Token refresh failed: {resp.text}")
                    data = resp.json()
                    account.access_token = data["access_token"]
                    expires_in = data.get("expires_in", 3600)
                    account.token_expiry = now + timedelta(seconds=expires_in)
                    db.commit()
        return account.access_token

    _locks: Dict[str, asyncio.Lock] = {}
    _locks_guard: Optional[asyncio.Lock] = None

    @classmethod
    def _get_guard(cls) -> asyncio.Lock:
        if cls._locks_guard is None:
            cls._locks_guard = asyncio.Lock()
        return cls._locks_guard

    @classmethod
    async def _get_message_lock(cls, key: str) -> asyncio.Lock:
        guard = cls._get_guard()
        async with guard:
            if key not in cls._locks:
                cls._locks[key] = asyncio.Lock()
            return cls._locks[key]

    @classmethod
    async def investigate_message(
        cls,
        account_email: str,
        message_id: str,
        db: Session,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        On-demand deep forensics investigation for a mailbox message.
        Guarantees idempotency via row-level locking + async lock and prevents IDOR via ownership check.
        """
        lock_key = f"{account_email}:{message_id}"
        msg_lock = await cls._get_message_lock(lock_key)

        async with msg_lock:
            # Refresh DB state to see any commit that just occurred
            db.expire_all()

            # --- 1. Ownership check (fixes IDOR & Tenant Isolation) ---
            account = db.query(GmailAccount).filter(
                func.lower(GmailAccount.email) == account_email.strip().lower()
            ).first()
            if account is None:
                raise HTTPException(status_code=404, detail="Mailbox not found")

            if current_user:
                if getattr(current_user, "role", "") != "admin":
                    is_owner_by_id = (account.owner_user_id is not None) and (account.owner_user_id == current_user.id)
                    is_owner_by_email = (account.email.strip().lower() == current_user.email.strip().lower())
                    if not (is_owner_by_id or is_owner_by_email):
                        raise HTTPException(status_code=404, detail="Mailbox not found")
            elif account.owner_user_id is not None:
                raise HTTPException(status_code=404, detail="Mailbox not found")

            # --- 2. Atomic idempotency check with row lock ---
            inbox_record = (
                db.query(InboxScanResult)
                .filter(
                    InboxScanResult.account_email == account_email,
                    InboxScanResult.message_id == message_id
                )
                .with_for_update()
                .first()
            )

            if inbox_record is None:
                raise HTTPException(status_code=404, detail="Message not found in scan history")

            if inbox_record.investigation_id:
                existing_inv = db.query(Investigation).filter(Investigation.id == inbox_record.investigation_id).first()
                return {
                    "messageId": message_id,
                    "investigationId": inbox_record.investigation_id,
                    "mode": "existing",
                    "sender": existing_inv.sender if existing_inv else inbox_record.sender,
                    "subject": existing_inv.subject if existing_inv else inbox_record.subject,
                    "verdict": existing_inv.verdict if existing_inv else inbox_record.verdict,
                }

            # --- 3. Check for demo mode / demo accounts ---
            raw_bytes = None
            if account.access_token.startswith("ya29.demo-"):
                env = os.getenv("ENVIRONMENT", "development").lower()
                if env in ("production", "prod"):
                    raise HTTPException(
                        status_code=400,
                        detail="Demo mailbox accounts are not permitted in production. Please connect a live Google Workspace / Gmail account."
                    )
                # Synthesize authentic EML bytes from message headers & snippet (no hardcoded demo_map fallback)
                now_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
                raw_bytes = (
                    f"From: {inbox_record.sender}\r\n"
                    f"To: {account.email}\r\n"
                    f"Subject: {inbox_record.subject}\r\n"
                    f"Date: {now_str}\r\n"
                    f"Message-ID: <{message_id}@mail.eval>\r\n"
                    f"Content-Type: text/plain; charset=UTF-8\r\n\r\n"
                    f"{inbox_record.snippet}\r\n"
                ).encode("utf-8")

            # --- 4. Fetch raw MIME from Gmail (for live accounts) ---
            if raw_bytes is None:
                try:
                    access_token = await cls._get_valid_access_token(account, db)
                except TokenRefreshError:
                    raise HTTPException(
                        status_code=401,
                        detail="Gmail authorization expired — please reconnect this account"
                    )

                try:
                    async with httpx.AsyncClient(timeout=15.0) as gmail_client:
                        resp = await gmail_client.get(
                            f"{cls.GMAIL_API_BASE}/messages/{message_id}",
                            params={"format": "raw"},
                            headers={"Authorization": f"Bearer {access_token}"}
                        )
                        if resp.status_code == 401:
                            # Token might have been revoked; attempt refresh once
                            access_token = await cls._get_valid_access_token(account, db)
                            resp = await gmail_client.get(
                                f"{cls.GMAIL_API_BASE}/messages/{message_id}",
                                params={"format": "raw"},
                                headers={"Authorization": f"Bearer {access_token}"}
                            )
                        if resp.status_code == 404:
                            raise HTTPException(status_code=404, detail="Message not found in Gmail mailbox")
                        resp.raise_for_status()
                        data = resp.json()
                except httpx.HTTPStatusError as e:
                    raise HTTPException(status_code=502, detail=f"Gmail API error: {e}")
                except httpx.TimeoutException:
                    raise HTTPException(status_code=504, detail="Gmail API timed out")

                raw_str = data.get("raw", "")
                if not raw_str:
                    raise HTTPException(status_code=502, detail="Gmail API returned empty raw MIME payload")

                padding = "=" * ((4 - len(raw_str) % 4) % 4)
                try:
                    raw_bytes = base64.urlsafe_b64decode((raw_str + padding).encode("ascii"))
                except Exception as e:
                    raise HTTPException(status_code=502, detail=f"Failed to decode MIME payload: {e}")

            # --- 5. Size guard before running the forensic pipeline ---
            if not raw_bytes:
                raise HTTPException(status_code=400, detail="Empty email payload cannot be investigated")

            MAX_EML_BYTES = 25 * 1024 * 1024  # 25 MB
            if len(raw_bytes) > MAX_EML_BYTES:
                raise HTTPException(status_code=413, detail="Message too large to investigate (exceeds 25MB)")

            # --- 6. Run the real forensic pipeline ---
            try:
                owner_id = current_user.id if current_user else account.owner_user_id
                new_inv = await EmailService.process_eml_file(
                    db=db,
                    content_bytes=raw_bytes,
                    filename=f"gmail_{message_id}.eml",
                    owner_user_id=owner_id
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.exception(f"process_eml_file failed for message_id={message_id}: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Forensic analysis pipeline failed: {type(e).__name__}: {str(e)}"
                )

            # --- 7. Persist association inside the locked transaction ---
            try:
                inbox_record.investigation_id = new_inv.id
                db.commit()
            except IntegrityError:
                db.rollback()
                db.refresh(inbox_record)
                return {
                    "messageId": message_id,
                    "investigationId": inbox_record.investigation_id,
                    "mode": "existing",
                }
            except Exception as assoc_err:
                db.rollback()
                logger.exception(f"Failed to persist inbox investigation association: {assoc_err}")
                raise HTTPException(status_code=500, detail=f"Failed to associate investigation with inbox: {assoc_err}")

            return {
                "messageId": message_id,
                "investigationId": new_inv.id,
                "mode": "live",
                "sender": new_inv.sender,
                "subject": new_inv.subject,
                "verdict": new_inv.verdict,
            }


inbox_service = InboxService()
