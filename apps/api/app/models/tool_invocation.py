"""Tool invocation record (SRS-07 Section 5.6): high-volume, TTL-bound telemetry."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.db.base import BaseDocument


class InvocationStatus(str, Enum):
    OK = "ok"
    TOOL_ERROR = "tool_error"
    VALIDATION_ERROR = "validation_error"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    AUTH_REQUIRED = "auth_required"
    TIMEOUT = "timeout"
    UPSTREAM_ERROR = "upstream_error"
    CIRCUIT_OPEN = "circuit_open"
    RATE_LIMITED = "rate_limited"
    DRY_RUN = "dry_run"


class ToolInvocation(BaseDocument):
    project_id: PydanticObjectId
    tool_key: str
    integration_id: Optional[PydanticObjectId] = None
    actor: Dict[str, Any] = Field(default_factory=dict)
    subject: Dict[str, Any] = Field(default_factory=dict)
    run_context: Dict[str, Any] = Field(default_factory=dict)
    origin: str = "runtime"
    status: InvocationStatus
    dry_run: bool = False
    arguments_redacted: Dict[str, Any] = Field(default_factory=dict)
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    latency_ms: Optional[int] = Field(default=None, ge=0)
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "tool_invocations"
        indexes = [
            IndexModel(
                [("project_id", ASCENDING), ("started_at", DESCENDING)],
                name="idx_tool_invocations_project_time",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("tool_key", ASCENDING), ("started_at", DESCENDING)],
                name="idx_tool_invocations_tool_time",
            ),
            # Retention (default 30 days; SRS-07 5.6)
            IndexModel(
                [("started_at", ASCENDING)],
                expireAfterSeconds=60 * 60 * 24 * 30,
                name="idx_tool_invocations_ttl",
            ),
        ]
