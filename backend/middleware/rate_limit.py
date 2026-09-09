"""
TraceMail AI Backend — In-Memory Rate Limiting Middleware
"""
import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, HTTPException, status

RATE_LIMIT_BURST = 60    # max 60 requests
RATE_LIMIT_WINDOW = 60   # per 60 seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._requests = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        
        # Clean expired timestamps
        history = self._requests.get(client_ip, [])
        history = [ts for ts in history if now - ts < RATE_LIMIT_WINDOW]
        
        if len(history) >= RATE_LIMIT_BURST:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait a moment before sending more requests."
            )
            
        history.append(now)
        self._requests[client_ip] = history
        
        return await call_next(request)
