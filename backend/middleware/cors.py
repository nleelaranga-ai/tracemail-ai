"""
TraceMail AI Backend — CORS Configuration Middleware
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.utils.config import settings


def setup_cors(app: FastAPI) -> None:
    allowed_origins = [
        "https://tracemail-ai-84ho.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://localhost:8001",
    ]

    # Include origins from config settings (excluding wildcard for credential safety)
    for origin in settings.BACKEND_CORS_ORIGINS:
        if origin != "*" and origin not in allowed_origins:
            allowed_origins.append(origin.rstrip("/"))

    # Add frontend URL from environment if provided
    frontend_url = os.getenv("FRONTEND_URL")
    if frontend_url and frontend_url.rstrip("/") not in allowed_origins:
        allowed_origins.append(frontend_url.rstrip("/"))

    # Add Vercel URL from environment if provided
    vercel_url = os.getenv("VERCEL_URL")
    if vercel_url:
        formatted_vercel = f"https://{vercel_url}" if not vercel_url.startswith("http") else vercel_url
        if formatted_vercel.rstrip("/") not in allowed_origins:
            allowed_origins.append(formatted_vercel.rstrip("/"))

    # Add comma-separated origins from CORS_ORIGINS environment variable
    cors_env = os.getenv("CORS_ORIGINS")
    if cors_env:
        for o in cors_env.split(","):
            cleaned = o.strip().rstrip("/")
            if cleaned and cleaned != "*" and cleaned not in allowed_origins:
                allowed_origins.append(cleaned)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
