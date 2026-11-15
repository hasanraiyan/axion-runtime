"""
Provider-neutral value objects for Module 07 (SRS-07 Sections 4.1 and 8).

Pure data, no I/O. Everything a caller needs to describe *who* is calling,
*what* to call, and *what came back*, independent of integration type.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from app.models.tool import Audience
from app.models.tool_invocation import InvocationStatus


class ActorType(str, Enum):
    USER = "user"
    MACHINE = "machine"
    RUNTIME = "runtime"


class SubjectType(str, Enum):
    PROJECT = "project"
    MEMBER = "member"
    END_USER = "end_user"


@dataclass(frozen=True)
class Actor:
    """The caller that makes the request."""

    type: ActorType
    id: str


@dataclass(frozen=True)
class Subject:
    """The identity on whose behalf a call runs. Never derived from model output."""

    type: SubjectType
    id: Optional[str] = None  # Clerk id (member) or ProjectEndUser id (end_user)
    external_id: Optional[str] = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable subject key: ``project``, ``member:{id}``, ``end_user:{id}``."""
        if self.type == SubjectType.PROJECT:
            return "project"
        return f"{self.type.value}:{self.id}"

    @property
    def audience(self) -> Audience:
        if self.type == SubjectType.MEMBER:
            return Audience.MEMBERS
        if self.type == SubjectType.END_USER:
            return Audience.END_USERS
        return Audience.MACHINE


@dataclass(frozen=True)
class PrincipalContext:
    project_id: str
    actor: Actor
    subject: Subject
    agent_id: Optional[str] = None
    run_id: Optional[str] = None
    origin: str = "runtime"  # runtime | playground | app_widget
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    member_role: Optional[str] = None  # project role of a human actor (viewer|member|admin|owner)

    def context_values(self) -> Dict[str, Optional[str]]:
        """Server-verified values usable for context-bound arguments (FR-76)."""
        values: Dict[str, Optional[str]] = {
            "project.id": self.project_id,
            "agent.id": self.agent_id,
            "run.id": self.run_id,
            "member.id": self.subject.id if self.subject.type == SubjectType.MEMBER else None,
            "end_user.id": self.subject.id if self.subject.type == SubjectType.END_USER else None,
            "end_user.external_id": self.subject.external_id if self.subject.type == SubjectType.END_USER else None,
        }
        if self.subject.type == SubjectType.END_USER:
            for key, value in self.subject.attributes.items():
                values[f"end_user.{key}"] = value
        return values


@dataclass(frozen=True)
class ContentBlock:
    type: str  # text | image | resource_link | data
    text: Optional[str] = None
    data: Any = None
    mime_type: Optional[str] = None


@dataclass
class InvocationRequest:
    project_id: str
    tool_key: str
    arguments: Dict[str, Any]
    principal: PrincipalContext
    idempotency_key: Optional[str] = None
    timeout_override_seconds: Optional[int] = None
    dry_run: bool = False
    approval_token: Optional[str] = None


@dataclass
class InvocationResult:
    status: InvocationStatus
    content: List[ContentBlock] = field(default_factory=list)
    structured_content: Any = None
    is_error: bool = False
    error_code: Optional[str] = None
    message: Optional[str] = None
    retryable: bool = False
    model_correctable: bool = False
    latency_ms: Optional[int] = None
    invocation_id: Optional[str] = None
    ui: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)  # e.g. approval payload, auth_required hints

    @property
    def ok(self) -> bool:
        return self.status in (InvocationStatus.OK, InvocationStatus.DRY_RUN) and not self.is_error


@dataclass(frozen=True)
class DiscoveredTool:
    """A tool definition as reported by a provider (before hashing and persistence)."""

    name: str
    description: str = ""
    title: Optional[str] = None
    input_schema: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    output_schema: Optional[Dict[str, Any]] = None
    annotations: Dict[str, Optional[bool]] = field(default_factory=dict)
    ui: Optional[Dict[str, Any]] = None
    # Trusted first-party adapters (native) may ship tools enabled; remote adapters never set this.
    default_enabled: bool = False


@dataclass(frozen=True)
class ProbeResult:
    healthy: bool
    latency_ms: Optional[int] = None
    status: str = "healthy"  # healthy | unreachable | auth_failed | rate_limited
    message: Optional[str] = None
    server_info: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawToolResult:
    """What an adapter returns; the Gateway normalizes it into an ``InvocationResult``."""

    content: List[ContentBlock] = field(default_factory=list)
    structured_content: Any = None
    is_error: bool = False
    error_message: Optional[str] = None


@dataclass(frozen=True)
class ResolvedTool:
    """A fully-resolved, effective tool as seen by the runtime and adapters."""

    tool_key: str
    integration_id: str
    integration_slug: str
    integration_type: str
    upstream_name: str
    description: str
    input_schema: Dict[str, Any]
    annotations: Dict[str, Optional[bool]]
    approval_policy: str
    timeout_seconds: int
    ui: Optional[Dict[str, Any]] = None
    config: Mapping[str, Any] = field(default_factory=dict)
    allowed_hosts: Optional[List[str]] = None
    # Effective configuration (SRS-07 5.2.2). ``input_schema`` is the full upstream schema used
    # for validation; ``visible_schema`` omits locked and context-bound parameters (shown to the model).
    visible_schema: Dict[str, Any] = field(default_factory=dict)
    definition_hash: str = ""
    locked_arguments: Mapping[str, Any] = field(default_factory=dict)
    default_arguments: Mapping[str, Any] = field(default_factory=dict)
    context_arguments: Mapping[str, str] = field(default_factory=dict)
    rate_limit_per_minute: Optional[int] = None
    per_end_user_rate_limit_per_minute: Optional[int] = None
    ui_visibility: Optional[List[str]] = None


class ResolvedCredentials:
    """In-memory credential material for one call. Never logged or serialized."""

    __slots__ = ("headers", "query")

    def __init__(self, headers: Optional[Dict[str, str]] = None, query: Optional[Dict[str, str]] = None) -> None:
        self.headers: Dict[str, str] = headers or {}
        self.query: Dict[str, str] = query or {}

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"ResolvedCredentials(headers={sorted(self.headers)}, query={sorted(self.query)})"

    __str__ = __repr__
