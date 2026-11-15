"""
``/metrics`` (Prometheus text format) for MOD-07 (SRS-07 NFR-O).

Off unless ``METRICS_TOKEN`` is configured; then every scrape needs ``Authorization: Bearer <token>``. The route is not
part of the OpenAPI contract. Series carry only bounded, non-tenant labels (see ``app.core.tools.telemetry``).
"""
import hmac
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from app.core.config import settings
from app.services.tools.providers import get_shared_tool_state

router = APIRouter()

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


@router.get("/metrics", include_in_schema=False)
async def metrics(authorization: Optional[str] = Header(default=None)) -> PlainTextResponse:
    token = settings.METRICS_TOKEN
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)  # not enabled: indistinguishable from no route
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Bearer"})
    return PlainTextResponse(get_shared_tool_state().telemetry.metrics.render(), media_type=PROMETHEUS_CONTENT_TYPE)
