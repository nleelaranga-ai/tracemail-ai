"""
TraceMail AI Backend — Authentication Router
"""
from fastapi import APIRouter, Depends, HTTPException, status
from backend.database.connection import get_db, Session
from backend.models.user import User
from backend.schemas.auth_schema import LoginRequest, RegisterRequest, AuthResponse, UserProfile
from backend.services.auth_service import AuthService
from backend.middleware.auth import require_auth

router = APIRouter(tags=["Authentication"])


@router.post("/api/v1/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@router.post("/api/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email address already exists."
        )

    user = AuthService.register_user(db, request.email, request.password, request.name)
    token = AuthService.create_access_token({"sub": user.email, "role": user.role, "id": user.id})

    return AuthResponse(
        token=token,
        user=UserProfile(id=user.id, email=user.email, name=user.name, role=user.role)
    )


@router.post("/api/v1/auth/login", response_model=AuthResponse)
@router.post("/api/auth/login", response_model=AuthResponse, include_in_schema=False)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = AuthService.authenticate_user(db, request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = AuthService.create_access_token({"sub": user.email, "role": user.role, "id": user.id})

    return AuthResponse(
        token=token,
        user=UserProfile(id=user.id, email=user.email, name=user.name, role=user.role)
    )


@router.get("/api/v1/auth/me", response_model=UserProfile)
def get_current_user_profile(user: User = Depends(require_auth)):
    return UserProfile(id=user.id, email=user.email, name=user.name, role=user.role)
