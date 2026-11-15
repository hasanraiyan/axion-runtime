"""
Invocation stages (SRS-07 FR-34): one concern each, composed in order by ``ToolExecutionGateway``.

Order: resolve -> subject state -> authorize -> context injection -> validate -> approve ->
rate limit -> circuit -> idempotency -> credentials -> execute -> normalize.
A stage returns an ``InvocationResult`` to short-circuit, or ``None`` to continue.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from app.core.exceptions import AppException, EndUserBlockedError, NotFoundError
from app.core.tools.errors import (
    UpstreamAuthError,
    UpstreamError,
    UpstreamRateLimited,
    UpstreamResponseTooLarge,
    UpstreamTargetBlocked,
    UpstreamTimeout,
)
from app.core.tools.ports import ToolExecutor, supports
from app.core.tools.registry import AdapterRegistry
from app.core.tools.resilience import CircuitBreaker, IdempotencyStore, SlidingWindowRateLimiter
from app.core.tools.signing import TokenSigner, arguments_hash
from app.core.tools.types import ContentBlock, InvocationResult, RawToolResult, SubjectType
from app.models.tool import ApprovalPolicy
from app.models.tool_invocation import InvocationStatus
from app.services.tools.credentials import AuthRequired, CredentialBuilder
from app.services.tools.end_user_service import EndUserService
from app.services.tools.gateway import InvocationState
from app.services.tools.health_service import IntegrationHealthService
from app.services.tools.toolset import ToolsetResolver

logger = logging.getLogger(__name__)

APPROVAL_PURPOSE = "tool_approval"
MAX_ARGUMENT_BYTES = 256 * 1024
MAX_RESULT_CHARS = 256 * 1024
MAX_VALIDATION_ERRORS = 5


def _fail(
    status: InvocationStatus,
    code: str,
    message: str,
    *,
    retryable: bool = False,
    correctable: bool = False,
    extra: Optional[Dict[str, Any]] = None,
) -> InvocationResult:
    return InvocationResult(
        status=status,
        is_error=True,
        error_code=code,
        message=message,
        retryable=retryable,
        model_correctable=correctable,
        extra=extra or {},
    )


class ResolveToolStage:
    def __init__(self, resolver: ToolsetResolver) -> None:
        self._resolver = resolver

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        request = state.request
        if request.project_id != request.principal.project_id:
            return _fail(InvocationStatus.DENIED, "tool_unavailable", "The tool is not available")
        try:
            context = await self._resolver.resolve_one(request.principal, request.tool_key)
        except (AppException, NotFoundError):
            return _fail(InvocationStatus.DENIED, "project_unavailable", "The project is not available")
        if context is None:
            return _fail(InvocationStatus.DENIED, "tool_unavailable", "The tool is not available")
        state.context = context
        return None


class SubjectStateStage:
    def __init__(self, end_users: EndUserService) -> None:
        self._end_users = end_users

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        subject = state.request.principal.subject
        if subject.type == SubjectType.END_USER and subject.id:
            try:
                await self._end_users.ensure_active(state.request.project_id, subject.id)
            except EndUserBlockedError:
                return _fail(InvocationStatus.DENIED, "end_user_blocked", "This user is not allowed to use tools")
        return None


class AuthorizeStage:
    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        principal = state.request.principal
        availability = context.availability
        tool = context.tool

        if availability.auth_required:
            return _fail(
                InvocationStatus.AUTH_REQUIRED,
                "auth_required",
                "The user must connect their account for this integration before the tool can run",
                extra={"integration": context.integration.slug, "connect_available": False},
            )
        if not availability.available:
            extra = {} if principal.subject.type == SubjectType.END_USER else {"reason": availability.reason}
            return _fail(InvocationStatus.DENIED, "tool_unavailable", "The tool is not available", extra=extra)

        read_only = tool.annotations.get("read_only") is True
        if (
            principal.origin == "playground"
            and principal.member_role not in ("admin", "owner")
            and not read_only
        ):
            return _fail(
                InvocationStatus.DENIED, "playground_requires_admin", "Only admins can test-run tools that may change data"
            )
        visibility = tool.ui_visibility
        if visibility is not None:
            if principal.origin == "app_widget" and "app" not in visibility:
                return _fail(InvocationStatus.DENIED, "tool_unavailable", "The tool is not available")
            if principal.origin != "app_widget" and "model" not in visibility:
                return _fail(InvocationStatus.DENIED, "app_only_tool", "This tool can only be called by its app")
        return None


class ContextInjectionStage:
    """Server-verified values overwrite anything the model supplied (SRS-07 FR-76)."""

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        tool = context.tool
        principal = state.request.principal

        arguments = dict(state.request.arguments)
        for name in set(tool.locked_arguments) | set(tool.context_arguments):
            arguments.pop(name, None)  # the model cannot set or override hidden parameters
        for name, value in tool.default_arguments.items():
            arguments.setdefault(name, value)
        arguments.update(tool.locked_arguments)

        values = principal.context_values()
        for name, key in tool.context_arguments.items():
            resolved = values.get(key)
            if resolved is None:
                return _fail(
                    InvocationStatus.VALIDATION_ERROR,
                    "context_unavailable",
                    "A value required by the integration is not available in this context",
                    extra={"context_key": key},
                )
            arguments[name] = resolved

        if len(json.dumps(arguments, default=str)) > MAX_ARGUMENT_BYTES:
            return _fail(InvocationStatus.VALIDATION_ERROR, "arguments_too_large", "The arguments are too large", correctable=True)
        state.arguments = arguments
        return None


class ValidationStage:
    """Strict validation: invalid input returns a correctable error and is never silently altered."""

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        schema = context.tool.input_schema or {}
        arguments = state.arguments

        properties = schema.get("properties")
        if isinstance(properties, dict) and schema.get("additionalProperties") is None:
            unknown = sorted(k for k in arguments if k not in properties)
            if unknown:
                return _fail(
                    InvocationStatus.VALIDATION_ERROR,
                    "argument_validation_failed",
                    f"Unknown argument(s): {', '.join(unknown[:5])}",
                    correctable=True,
                )
        try:
            validator_class = validator_for(schema, default=Draft202012Validator)
            validator_class.check_schema(schema)
            errors = sorted(validator_class(schema).iter_errors(arguments), key=lambda e: list(e.path))
        except SchemaError:
            logger.warning("Tool %s has an unusable input schema; skipping validation", context.tool.tool_key)
            return None
        if errors:
            details = []
            for error in errors[:MAX_VALIDATION_ERRORS]:
                location = ".".join(str(p) for p in error.path) or "(arguments)"
                details.append(f"{location}: {error.message[:200]}")
            return _fail(
                InvocationStatus.VALIDATION_ERROR,
                "argument_validation_failed",
                "Invalid arguments: " + "; ".join(details),
                correctable=True,
                extra={"errors": details},
            )
        return None


class ApprovalStage:
    def __init__(self, signer: TokenSigner) -> None:
        self._signer = signer

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        request = state.request
        policy = ApprovalPolicy(context.tool.approval_policy)
        if policy == ApprovalPolicy.AUTO or request.dry_run:
            return None
        if policy == ApprovalPolicy.DENY:
            return _fail(InvocationStatus.DENIED, "tool_denied", "This tool is not allowed")

        token = request.approval_token
        if token:
            try:
                claims = self._signer.verify(token, APPROVAL_PURPOSE)
                if (
                    claims.get("prj") == request.project_id
                    and claims.get("tool") == request.tool_key
                    and claims.get("sub") == request.principal.subject.key
                    and claims.get("args") == arguments_hash(request.arguments)
                ):
                    return None
            except AppException:
                pass
        from app.core.tools.redaction import redact_arguments

        return InvocationResult(
            status=InvocationStatus.APPROVAL_REQUIRED,
            is_error=True,
            error_code="approval_required",
            message="This tool call needs approval before it can run",
            extra={
                "approval": {
                    "tool_key": request.tool_key,
                    "arguments": redact_arguments(request.arguments),
                    "reason": "approval_policy",
                }
            },
        )


class RateLimitStage:
    def __init__(self, limiter: SlidingWindowRateLimiter) -> None:
        self._limiter = limiter

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        tool = context.tool
        request = state.request
        subject = request.principal.subject
        if not self._limiter.check_and_hit(f"tool:{request.project_id}:{tool.tool_key}", tool.rate_limit_per_minute):
            return _fail(InvocationStatus.RATE_LIMITED, "rate_limited", "Too many calls to this tool; retry shortly", retryable=True)
        if subject.type == SubjectType.END_USER and not self._limiter.check_and_hit(
            f"eu:{request.project_id}:{tool.tool_key}:{subject.id}", tool.per_end_user_rate_limit_per_minute
        ):
            return _fail(InvocationStatus.RATE_LIMITED, "rate_limited", "Too many calls; retry shortly", retryable=True)
        return None


class CircuitStage:
    def __init__(self, breaker: CircuitBreaker) -> None:
        self._breaker = breaker

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        if self._breaker.is_open(context.tool.integration_id):
            return _fail(
                InvocationStatus.CIRCUIT_OPEN, "circuit_open", "The integration is temporarily unavailable", retryable=True
            )
        return None


class IdempotencyStage:
    def __init__(self, store: IdempotencyStore) -> None:
        self._store = store

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        request = state.request
        if not request.idempotency_key or context.tool.annotations.get("read_only") is True or request.dry_run:
            return None
        state.idempotency_cache_key = "|".join(
            [request.project_id, request.tool_key, request.principal.subject.key, request.idempotency_key, arguments_hash(request.arguments)]
        )
        cached = self._store.get(state.idempotency_cache_key)
        if isinstance(cached, InvocationResult):
            replay = InvocationResult(**{**cached.__dict__, "extra": {**cached.extra, "idempotent_replay": True}})
            return replay
        return None

    async def after(self, state: InvocationState, result: InvocationResult) -> None:
        if state.idempotency_cache_key and result.ok and not result.extra.get("idempotent_replay"):
            self._store.put(state.idempotency_cache_key, result)


class CredentialStage:
    def __init__(self, credentials: CredentialBuilder) -> None:
        self._credentials = credentials

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        if state.request.dry_run and context.tool.annotations.get("read_only") is not True:
            return None  # nothing is sent in a dry run, so no credential is needed
        try:
            state.credentials = await self._credentials.resolve(context.integration, state.request.principal.subject)
        except AuthRequired:
            return _fail(
                InvocationStatus.AUTH_REQUIRED,
                "auth_required",
                "The user must connect their account for this integration before the tool can run",
                extra={"integration": context.integration.slug, "connect_available": False},
            )
        except AppException:
            return _fail(
                InvocationStatus.UPSTREAM_ERROR,
                "integration_misconfigured",
                "The integration is misconfigured; an administrator must fix it",
            )
        return None


class ExecuteStage:
    def __init__(
        self,
        adapters: AdapterRegistry,
        breaker: CircuitBreaker,
        health: IntegrationHealthService,
    ) -> None:
        self._adapters = adapters
        self._breaker = breaker
        self._health = health

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        request = state.request
        tool = context.tool
        integration = context.integration

        if request.dry_run and tool.annotations.get("read_only") is not True:
            return InvocationResult(
                status=InvocationStatus.DRY_RUN,
                content=[ContentBlock(type="text", text=f"[dry run] {tool.tool_key} was validated but not executed")],
                structured_content={"dry_run": True, "arguments": state.arguments},
            )

        adapter = self._adapters.for_integration(integration)
        if not supports(adapter, ToolExecutor):
            return _fail(InvocationStatus.UPSTREAM_ERROR, "not_executable", "This integration cannot run tools")

        timeout = min(request.timeout_override_seconds or tool.timeout_seconds, 300)
        key = tool.integration_id
        try:
            async with asyncio.timeout(timeout):
                raw = await adapter.execute(integration, tool, state.arguments, state.credentials, timeout)
        except (UpstreamTimeout, TimeoutError):
            return await self._failure(integration, key, InvocationStatus.TIMEOUT, "upstream_timeout", "The tool timed out", True)
        except UpstreamAuthError:
            await self._health.mark_error(integration, "Upstream rejected the credentials")
            return _fail(
                InvocationStatus.UPSTREAM_ERROR,
                "upstream_auth_failed",
                "The integration's credentials were rejected; an administrator must fix this",
            )
        except UpstreamRateLimited:
            return _fail(InvocationStatus.RATE_LIMITED, "upstream_rate_limited", "The upstream rate limit was reached", retryable=True)
        except UpstreamTargetBlocked:
            return _fail(InvocationStatus.UPSTREAM_ERROR, "target_blocked", "The integration target is not permitted")
        except UpstreamResponseTooLarge:
            return _fail(InvocationStatus.UPSTREAM_ERROR, "result_too_large", "The tool result was too large")
        except UpstreamError:
            return await self._failure(integration, key, InvocationStatus.UPSTREAM_ERROR, "upstream_error", "The upstream service failed", True)
        except Exception:
            logger.exception("Adapter failure for %s", tool.tool_key)
            return await self._failure(integration, key, InvocationStatus.UPSTREAM_ERROR, "adapter_error", "The tool failed unexpectedly", True)

        self._breaker.record_success(key)
        await self._health.mark_recovered(integration)
        state.raw = raw
        return None

    async def _failure(self, integration, key: str, status: InvocationStatus, code: str, message: str, retryable: bool) -> InvocationResult:
        if self._breaker.record_failure(key):
            await self._health.mark_degraded(integration, "Repeated upstream failures")
        return _fail(status, code, message, retryable=retryable)


class NormalizeStage:
    """Turn an adapter's raw result into the uniform envelope (FR-33, FR-34, FR-78)."""

    async def run(self, state: InvocationState) -> Optional[InvocationResult]:
        context = state.context
        assert context is not None
        raw: RawToolResult = state.raw or RawToolResult()

        blocks: List[ContentBlock] = []
        remaining = MAX_RESULT_CHARS
        truncated = False
        for block in raw.content:
            if block.type == "text" and block.text is not None:
                if len(block.text) > remaining:
                    truncated = True
                    blocks.append(ContentBlock(type="text", text=block.text[: max(remaining, 0)]))
                    remaining = 0
                else:
                    remaining -= len(block.text)
                    blocks.append(block)
            else:
                blocks.append(block)

        ui = None
        if context.tool.ui:
            ui = {"resource_uri": context.tool.ui.get("resource_uri"), "integration_id": context.tool.integration_id}

        if raw.is_error:
            return InvocationResult(
                status=InvocationStatus.TOOL_ERROR,
                content=blocks,
                structured_content=raw.structured_content,
                is_error=True,
                error_code="tool_error",
                message=(raw.error_message or "The tool reported an error")[:500],
                model_correctable=True,
                ui=ui,
            )
        return InvocationResult(
            status=InvocationStatus.OK,
            content=blocks,
            structured_content=raw.structured_content,
            ui=ui,
            extra={"truncated": True} if truncated else {},
        )


def build_stages(
    resolver: ToolsetResolver,
    end_users: EndUserService,
    signer: TokenSigner,
    limiter: SlidingWindowRateLimiter,
    breaker: CircuitBreaker,
    idempotency: IdempotencyStore,
    credentials: CredentialBuilder,
    adapters: AdapterRegistry,
    health: IntegrationHealthService,
) -> List[Any]:
    """The default ordered pipeline."""
    return [
        ResolveToolStage(resolver),
        SubjectStateStage(end_users),
        AuthorizeStage(),
        ContextInjectionStage(),
        ValidationStage(),
        ApprovalStage(signer),
        RateLimitStage(limiter),
        CircuitStage(breaker),
        IdempotencyStage(idempotency),
        CredentialStage(credentials),
        ExecuteStage(adapters, breaker, health),
        NormalizeStage(),
    ]
