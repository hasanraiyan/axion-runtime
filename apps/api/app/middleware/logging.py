import logging
import re
import time
from typing import Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("app.http")

# Path regex matching sensitive secret routes where request/response bodies must never be logged
REDACT_PATHS_REGEX = re.compile(r"/(secrets|reveal|resolve)(?:/|$|\?)", re.IGNORECASE)
REDACTED_PATHS_REGEX = REDACT_PATHS_REGEX
REDACTED_BODY = "[REDACTED]"
REDACTED_PLACEHOLDER = "[REDACTED]"


def is_redacted_path(path: str) -> bool:
    """Check if the given request path matches sensitive endpoints requiring body redaction."""
    return bool(REDACT_PATHS_REGEX.search(path))


def should_redact(path: str) -> bool:
    """Check whether request/response payloads for this path should be redacted."""
    return is_redacted_path(path)


def redact_body(path: str, body: Any) -> Any:
    """Redacts request or response body if the endpoint path is sensitive."""
    if is_redacted_path(path):
        return REDACTED_BODY
    return body


def redact_payload(path: str, payload: Any) -> Any:
    """Redacts arbitrary payload dictionaries or strings for sensitive paths."""
    if is_redacted_path(path):
        return REDACTED_BODY
    return payload


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that records structured request access logs and execution timing.
    Guarantees zero plaintext exposure by redacting request/response bodies for
    sensitive routes (/secrets, /reveal, /resolve).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        method = request.method
        url = request.url.path
        client_ip = request.client.host if request.client else "unknown"
        is_sensitive = is_redacted_path(url)

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_msg = f"{method} {url} - {response.status_code} ({duration_ms}ms) [{client_ip}]"
            if is_sensitive:
                log_msg += " [BODY REDACTED]"
            logger.info(log_msg)
            response.headers["X-Response-Time-Ms"] = str(duration_ms)
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_msg = f"{method} {url} - FAILED ({duration_ms}ms) [{client_ip}] - {exc}"
            if is_sensitive:
                log_msg += " [BODY REDACTED]"
            logger.error(log_msg)
            raise exc
