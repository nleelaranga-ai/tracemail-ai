"""
TraceMail AI Backend — Authentication Schemas
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: Optional[str] = "SOC Analyst"


class UserProfile(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    role: str = "analyst"


class AuthResponse(BaseModel):
    token: str
    user: UserProfile
