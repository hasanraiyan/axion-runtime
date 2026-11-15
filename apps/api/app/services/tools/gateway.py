"""
ToolExecutionGateway (SRS-07 FR-33..FR-39): the single entry point for every tool call.

The Gateway only *composes* ordered ``InvocationStage`` objects, converts unexpected failures into
a structured result, and hands the outcome to the recorder. Every concern (authorization,
validation, approval, limits, credentials, execution, normalization) lives in its own stage in
``gateway_stages``. Adding a concern means adding a stage, not editing the Gateway.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from app.core.tools.redaction import redact_arguments
from app.core.tools.types import InvocationRequest, InvocationResult, RawToolResult, ResolvedCredentials
from app.core.protocols.tool_repositories import IToolInvocationRepository
from app.core.tools.ports import AuditPort
from app.models.project import ProjectAuditAction
from app.models.tool_invocation import InvocationStatus, ToolInvocation
from app.services.tools.toolset import ToolContext

logger = logging.getLogger(__name__)


@dataclass
class InvocationState:
    request: InvocationRequest
    context: Optional[ToolContext] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    credentials: Optional[ResolvedCredentials] = None
    raw: Optional[RawToolResult] = None
    started: float = field(default_factory=time.monotonic)
    idempotency_cache_key: Optional[str] = None
    notes: Dict[str, Any] = field(default_factory=dict)


class InvocationStage(Protocol):
    """One concern. Return a result to short-circuit, or ``None`` to continue."""

    async def run(self, state: InvocationState) -> Optional[InvocationResult]: ...


class InvocationRecorder:
    """Persists invocation telemetry (always) and audit events (sensitive calls only)."""

    def __init__(self, invocation_repo: IToolInvocationRepository, audit: AuditPort) -> None:
        self._invocations = invocation_repo
        self._audit = audit

    async def record(self, state: InvocationState, result: InvocationResult) -> Optional[str]:
        request = state.request
        context = state.context
        principal = request.principal
        hidden = set(context.tool.context_arguments) | set(context.tool.locked_arguments) if context else set()
        try:
            document = ToolInvocation(
                project_id=request.project_id,
                tool_key=request.tool_key,
                integration_id=context.integration.id if context else None,
                actor={"type": principal.actor.type.value, "id": principal.actor.id},
                subject={
                    "type": principal.subject.type.value,
                    "id": principal.subject.id,
                    "external_id": principal.subject.external_id,
                },
                run_context={"agent_id": principal.agent_id, "run_id": principal.run_id},
                origin=principal.origin,
                status=result.status,
                dry_run=request.dry_run,
                arguments_redacted=redact_arguments(request.arguments, hidden),
                result_summary={
                    "is_error": result.is_error,
                    "error_code": result.error_code,
                    "blocks": [b.type for b in result.content],
                },
                latency_ms=result.latency_ms,
                trace_id=principal.trace_id,
                request_id=principal.request_id,
            )
            saved = await self._invocations.create(document)
            invocation_id = str(saved.id)
        except Exception:
            logger.exception("Failed to record tool invocation")
            invocation_id = None

        sensitive = (
            result.status in (InvocationStatus.DENIED, InvocationStatus.APPROVAL_REQUIRED)
            or principal.origin == "playground"
            or (context is not None and context.tool.annotations.get("destructive") is True)
        )
        if sensitive:
            try:
                await self._audit.record(
                    request.project_id,
                    principal.actor.id,
                    ProjectAuditAction.TOOL_INVOKED.value,
                    {
                        "tool_key": request.tool_key,
                        "status": result.status.value,
                        "subject_type": principal.subject.type.value,
                        "origin": principal.origin,
                        "invocation_id": invocation_id,
                    },
                )
            except Exception:
                logger.exception("Failed to audit sensitive tool invocation")
        return invocation_id


class ToolExecutionGateway:
    def __init__(self, stages: List[InvocationStage], recorder: InvocationRecorder) -> None:
        self._stages = stages
        self._recorder = recorder

    async def invoke(self, request: InvocationRequest) -> InvocationResult:
        state = InvocationState(request=request, arguments=dict(request.arguments))
        result: Optional[InvocationResult] = None
        try:
            for stage in self._stages:
                result = await stage.run(state)
                if result is not None:
                    break
        except Exception:  # a stage bug must never crash an agent run (FR-78)
            logger.exception("Unhandled error in tool invocation pipeline")
            result = InvocationResult(
                status=InvocationStatus.UPSTREAM_ERROR,
                is_error=True,
                error_code="internal_error",
                message="The tool could not be run because of an internal error",
            )

        if result is None:  # defensive: the last stage always returns
            result = InvocationResult(
                status=InvocationStatus.UPSTREAM_ERROR, is_error=True, error_code="no_result", message="No result produced"
            )

        result.latency_ms = int((time.monotonic() - state.started) * 1000)
        for stage in reversed(self._stages):
            after = getattr(stage, "after", None)
            if after is not None:
                try:
                    await after(state, result)
                except Exception:
                    logger.exception("Gateway stage post-processing failed")
        result.invocation_id = await self._recorder.record(state, result)
        return result
