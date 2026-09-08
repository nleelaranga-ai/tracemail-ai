"""
TraceMail AI Backend — JWT Auth Middleware & Dependencies
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from backend.database.connection import get_db, Session
from backend.models.user import User
from backend.services.auth_service import AuthService

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Dependency for extracting the authenticated user. Allows public fallbacks if needed."""
    if not credentials:
        return None

    token = credentials.credentials
    payload = AuthService.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_email = payload.get("sub")
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing subject identifier.",
        )

    user = db.query(User).filter(User.email == user_email).first()
    return user


async def require_auth(user: Optional[User] = Depends(get_current_user)) -> User:
    """Strict dependency requiring authenticated user."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access this endpoint.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
