"""
TraceMail AI Backend — In-Memory Rate Limiting Middleware
"""
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request, status

RATE_LIMIT_BURST = 120   # max 120 requests
RATE_LIMIT_WINDOW = 60   # per 60 seconds

EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._requests = {}

    async def dispatch(self, request: Request, call_next):
        # Always allow CORS preflight requests and health checks
        if request.method == "OPTIONS" or request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        
        # Clean expired timestamps
        history = self._requests.get(client_ip, [])
        history = [ts for ts in history if now - ts < RATE_LIMIT_WINDOW]
        
        if len(history) >= RATE_LIMIT_BURST:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please wait a moment before sending more requests."}
            )
            
        history.append(now)
        self._requests[client_ip] = history
        
        return await call_next(request)

