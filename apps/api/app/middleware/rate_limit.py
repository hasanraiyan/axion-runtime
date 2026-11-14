import time
from collections import defaultdict
from typing import Dict, List
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse


class InMemoryRateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Sliding window in-memory rate limiter per client IP.
    """

    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.rate_limit = requests_per_minute
        self.request_records: Dict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # Skip rate limiting for health endpoints and docs
        path = request.url.path
        if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi.json") or path.endswith("/health"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        window_start = now - 60.0

        # Purge timestamps older than 60 seconds
        timestamps = [ts for ts in self.request_records[client_ip] if ts > window_start]
        self.request_records[client_ip] = timestamps

        if len(timestamps) >= self.rate_limit:
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Rate limit of {self.rate_limit} requests per minute exceeded.",
                        "details": [],
                    },
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.rate_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        self.request_records[client_ip].append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.rate_limit - len(self.request_records[client_ip])))
        return response
