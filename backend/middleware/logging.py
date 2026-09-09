"""
TraceMail AI Backend — Request Logging Middleware
"""
import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from backend.utils.logger import logger


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000.0
        
        # Don't clutter logs for root docs or health polls
        if request.url.path not in ["/health", "/docs", "/openapi.json"]:
            logger.info(
                f"{request.method} {request.url.path} -> Status {response.status_code} "
                f"({process_time:.2f}ms)"
            )
        return response
