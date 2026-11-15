"""
McpAppService (SRS-07 FR-45..FR-51): MCP App resources, approval, rendering, and the app bridge.

Third-party HTML is untrusted. This service fetches it through the adapter (so the Outbound Guard applies),
pins its SHA-256, and releases it only if an admin approved that exact hash together with specific domains and
browser permissions. The bridge lets an approved widget call tools and read resources, but only within its own
integration, only for tools that declare the app as a caller, and always through the Execution Gateway so
authorization, validation, approval, rate limits, and audit still apply (an app is never a back door).
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import (
    AppNotApprovedError,
    AppOriginViolationError,
    BadRequestError,
    ConflictError,
    NotFoundError,
    UpstreamFailureError,
)
from app.core.protocols.tool_repositories import (
    IAppResourceRepository,
    IIntegrationRepository,
    IToolDefinitionRepository,
)
from app.core.tools.errors import UpstreamError
from app.core.tools.ports import AuditPort, PromptProvider, ResourceReader, ToolExecutionPort, supports
from app.core.tools.registry import AdapterRegistry
from app.core.tools.resilience import SlidingWindowRateLimiter
from app.core.tools.types import (
    FetchedResource,
    InvocationRequest,
    InvocationResult,
    PrincipalContext,
    PromptInfo,
    ResolvedCredentials,
    ResourceInfo,
    Subject,
    SubjectType,
)
from app.models.app_resource import CSP_CATEGORIES, PERMISSIONS, AppResource, AppSyncState
from app.models.integration import EndUserAccess, Integration
from app.models.project import ProjectAuditAction
from app.models.tool_invocation import InvocationStatus
from app.services.tools.common import ProjectLifecycle
from app.services.tools.credentials import AuthRequired, CredentialBuilder

IdLike = Union[str, PydanticObjectId, ObjectId]
APP_MAX_BYTES = 2 * 1024 * 1024
READ_MAX_BYTES = 1024 * 1024
MAX_DOMAINS_PER_CATEGORY = 20
BRIDGE_CALLS_PER_MINUTE = 60
APP_MIME_PREFIX = "text/html"


def normalize_app_origin(value: Any) -> Optional[str]:
    """``https://host[:port]`` or ``wss://host[:port]`` only: no wildcards, paths, credentials, or other schemes."""
    if not isinstance(value, str) or "*" in value:
        return None
    try:
        parts = urlparse(value.strip())
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "wss") or not host or parts.username or parts.password:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def parse_declared(meta: Dict[str, Any]) -> Tuple[Dict[str, List[str]], List[str]]:
    """Extract the CSP domains and browser permissions an app *asks for*; anything malformed is dropped."""
    ui = meta.get("ui") if isinstance(meta.get("ui"), dict) else {}
    csp_raw = ui.get("csp") if isinstance(ui.get("csp"), dict) else {}
    csp: Dict[str, List[str]] = {}
    for category in CSP_CATEGORIES:
        values = csp_raw.get(category)
        if isinstance(values, list):
            cleaned = sorted({o for o in (normalize_app_origin(v) for v in values) if o})[:MAX_DOMAINS_PER_CATEGORY]
            if cleaned:
                csp[category] = cleaned
    perms_raw = ui.get("permissions") if isinstance(ui.get("permissions"), dict) else {}
    return csp, sorted(p for p in perms_raw if p in PERMISSIONS)


def template_matches(template: str, uri: str) -> bool:
    """Level-1 URI template match (``docs://{name}``): each variable matches one path segment."""
    pattern = "".join("[^/?#]+" if part.startswith("{") else re.escape(part) for part in re.split(r"(\{[^}]+\})", template) if part)
    return re.fullmatch(pattern, uri) is not None


@dataclass
class AppSyncSummary:
    synced: List[str] = field(default_factory=list)
    changed: List[str] = field(default_factory=list)
    unavailable: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RenderableApp:
    resource_id: str
    integration_id: str
    uri: str
    mime_type: Optional[str]
    html: str
    content_hash: str
    csp: Dict[str, List[str]]
    permissions: List[str]


class McpAppService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        tool_repo: IToolDefinitionRepository,
        app_repo: IAppResourceRepository,
        adapters: AdapterRegistry,
        credentials: CredentialBuilder,
        gateway: ToolExecutionPort,
        limiter: SlidingWindowRateLimiter,
        audit: AuditPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._tools = tool_repo
        self._apps = app_repo
        self._adapters = adapters
        self._credentials = credentials
        self._gateway = gateway
        self._limiter = limiter
        self._audit = audit

    # ------------------------------------------------------------------ helpers
    async def _integration(self, project_id: Any, integration_id: IdLike) -> Integration:
        integration = await self._integrations.get_by_id_and_project(integration_id, project_id)
        if integration is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        return integration

    def _adapter(self, integration: Integration, role: type) -> Any:
        adapter = self._adapters.for_integration(integration)
        if not supports(adapter, role):
            raise BadRequestError("This integration type does not provide MCP resources")
        return adapter

    async def _creds(self, integration: Integration, subject: Subject) -> ResolvedCredentials:
        try:
            return await self._credentials.resolve(integration, subject)
        except AuthRequired:
            err = BadRequestError("Connect an account for this integration first")
            err.code = "AUTH_REQUIRED"
            raise err from None
        except UpstreamError as exc:
            raise self._upstream(exc) from exc

    @staticmethod
    def _upstream(exc: UpstreamError) -> UpstreamFailureError:
        return UpstreamFailureError(f"The MCP server failed: {str(exc)[:200]}")

    # ------------------------------------------------------------------- listing
    async def list_resources(self, project_id: IdLike, integration_id: IdLike, subject: Subject) -> List[ResourceInfo]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        integration = await self._integration(project.id, integration_id)
        adapter = self._adapter(integration, ResourceReader)
        creds = await self._creds(integration, subject)
        try:
            return await adapter.list_resources(integration, creds) + await adapter.list_resource_templates(integration, creds)
        except UpstreamError as exc:
            raise self._upstream(exc) from exc

    async def list_prompts(self, project_id: IdLike, integration_id: IdLike, subject: Subject) -> List[PromptInfo]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        integration = await self._integration(project.id, integration_id)
        adapter = self._adapter(integration, PromptProvider)
        creds = await self._creds(integration, subject)
        try:
            return await adapter.list_prompts(integration, creds)
        except UpstreamError as exc:
            raise self._upstream(exc) from exc

    async def list_apps(self, project_id: IdLike, integration_id: IdLike) -> List[AppResource]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        await self._integration(project.id, integration_id)
        return await self._apps.list_by_integration(project.id, integration_id)

    # ---------------------------------------------------------------------- sync
    async def sync_integration(
        self, project_id: IdLike, integration_id: IdLike, actor_id: str, subject: Optional[Subject] = None
    ) -> AppSyncSummary:
        """Fetch every ``ui://`` resource the integration's tools reference and pin its hash (FR-45)."""
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integration(project.id, integration_id)
        adapter = self._adapter(integration, ResourceReader)
        creds = await self._creds(integration, subject or Subject(SubjectType.PROJECT))

        uris = sorted({d.ui.resource_uri for d in await self._tools.list_by_integration(integration.id) if d.ui and d.ui.resource_uri})
        summary = AppSyncSummary()
        for uri in uris:
            existing = await self._apps.get_by_uri(integration.id, uri)
            try:
                if not uri.startswith("ui://"):
                    raise BadRequestError("App resources must use the ui:// scheme")
                fetched = await adapter.read_resource(integration, creds, uri, APP_MAX_BYTES)
                self._validate_app(fetched)
            except (UpstreamError, BadRequestError) as exc:
                reason = str(getattr(exc, "message", exc))[:200]
                await self._mark_unavailable(project.id, integration, uri, existing, reason)
                summary.unavailable.append({"uri": uri, "reason": reason})
                continue
            changed = await self._store(project.id, integration, uri, fetched, existing)
            (summary.changed if changed else summary.synced).append(uri)

        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.APP_RESOURCE_SYNCED.value,
            {"integration_id": str(integration.id), "synced": len(summary.synced), "changed": len(summary.changed), "unavailable": len(summary.unavailable)},
        )
        return summary

    @staticmethod
    def _validate_app(fetched: FetchedResource) -> None:
        if fetched.text is None or not (fetched.mime_type or "").lower().startswith(APP_MIME_PREFIX):
            raise BadRequestError("An app resource must be text/html")

    async def _store(self, project_id: Any, integration: Integration, uri: str, fetched: FetchedResource, existing: Optional[AppResource]) -> bool:
        """Upsert one app resource; return True if its content changed under an existing approval."""
        content = fetched.text or ""
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        csp, permissions = parse_declared(fetched.meta)
        state = AppSyncState.IN_SYNC
        changed = False
        if existing is not None and existing.content_hash != digest and existing.approved_hash not in (None, digest):
            state, changed = AppSyncState.CHANGED, True  # approved content was replaced: blocked until re-approved
        document = AppResource(
            project_id=project_id, integration_id=integration.id, uri=uri, mime_type=fetched.mime_type, content=content,
            content_hash=digest, size_bytes=fetched.size_bytes, declared_csp=csp, declared_permissions=permissions,
            approved_hash=existing.approved_hash if existing else None,
            approved_csp=existing.approved_csp if existing else {},
            approved_permissions=existing.approved_permissions if existing else [],
            approved_by=existing.approved_by if existing else None,
            approved_at=existing.approved_at if existing else None,
            sync_state=state, status_message=None, fetched_at=datetime.now(timezone.utc),
        )
        await self._apps.save(document)
        return changed

    async def _mark_unavailable(self, project_id: Any, integration: Integration, uri: str, existing: Optional[AppResource], reason: str) -> None:
        if existing is None:
            await self._apps.save(
                AppResource(project_id=project_id, integration_id=integration.id, uri=uri, sync_state=AppSyncState.UNAVAILABLE, status_message=reason)
            )
        else:
            await self._apps.update_with_revision(existing.id, existing.revision, {"sync_state": AppSyncState.UNAVAILABLE, "status_message": reason})

    # ------------------------------------------------------------------ approval
    async def approve(
        self,
        project_id: IdLike,
        resource_id: IdLike,
        content_hash: str,
        csp: Dict[str, List[str]],
        permissions: List[str],
        actor_id: str,
    ) -> AppResource:
        """
        Approve exactly ``content_hash`` with exactly the listed domains and permissions (FR-46).
        Anything not listed is denied; the hash must be the one the admin reviewed.
        """
        project = await self._lifecycle.get_active(project_id)
        resource = await self._apps.get_by_id_and_project(resource_id, project.id)
        if resource is None:
            raise NotFoundError("App resource not found")
        if resource.sync_state == AppSyncState.UNAVAILABLE:
            raise ConflictError("The server no longer serves this app; sync it again before approving")
        if content_hash != resource.content_hash:
            err = ConflictError("The app changed since you reviewed it; review the current version")
            err.code = "APP_CONTENT_CHANGED"
            raise err

        granted: Dict[str, List[str]] = {}
        for category, origins in csp.items():
            if category not in CSP_CATEGORIES:
                raise BadRequestError(f"Unknown CSP category '{category[:40]}'")
            normalized = [normalize_app_origin(o) for o in origins]
            if any(o is None for o in normalized) or not set(normalized) <= set(resource.declared_csp.get(category, [])):
                raise BadRequestError(f"{category}: only domains the app declared can be approved")
            if normalized:
                granted[category] = sorted(set(normalized))  # type: ignore[arg-type]
        if not set(permissions) <= set(resource.declared_permissions):
            raise BadRequestError("Only permissions the app declared can be approved")

        updated = await self._apps.update_with_revision(
            resource.id, resource.revision,
            {
                "approved_hash": resource.content_hash, "approved_csp": granted, "approved_permissions": sorted(set(permissions)),
                "approved_by": actor_id, "approved_at": datetime.now(timezone.utc), "sync_state": AppSyncState.IN_SYNC,
            },
        )
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.APP_RESOURCE_APPROVED.value,
            {"resource_id": str(resource.id), "uri": resource.uri, "content_hash": resource.content_hash, "csp": granted, "permissions": sorted(set(permissions))},
        )
        return updated

    # ------------------------------------------------------------------- render
    async def _require_renderable(self, project_id: Any, resource_id: IdLike, subject: Subject) -> Tuple[AppResource, Integration]:
        resource = await self._apps.get_by_id_and_project(resource_id, project_id)
        if resource is None:
            raise NotFoundError("App resource not found")
        integration = await self._integrations.get_by_id_and_project(resource.integration_id, project_id)
        if integration is None or not integration.is_enabled:
            raise NotFoundError("App resource not found")
        if subject.type == SubjectType.END_USER and integration.end_user_access != EndUserAccess.OPEN:
            raise NotFoundError("App resource not found")  # indistinguishable from "does not exist"
        if not resource.is_approved:
            raise AppNotApprovedError()
        return resource, integration

    async def render(self, project_id: IdLike, resource_id: IdLike, subject: Subject) -> RenderableApp:
        """Approved HTML with its *approved* domains and permissions only; the host must not loosen them (FR-47)."""
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        resource, _ = await self._require_renderable(project.id, resource_id, subject)
        csp = {c: [o for o in origins if o in resource.declared_csp.get(c, [])] for c, origins in resource.approved_csp.items()}
        permissions = [p for p in resource.approved_permissions if p in resource.declared_permissions]
        return RenderableApp(
            resource_id=str(resource.id), integration_id=str(resource.integration_id), uri=resource.uri, mime_type=resource.mime_type,
            html=resource.content, content_hash=resource.content_hash, csp=csp, permissions=permissions,
        )

    # ------------------------------------------------------------------- bridge
    async def call_tool(
        self,
        principal: PrincipalContext,
        resource_id: IdLike,
        tool_key: str,
        arguments: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> InvocationResult:
        """An approved app calls a tool. Same integration only, then the full gateway pipeline (FR-48)."""
        project = await self._lifecycle.get_active(principal.project_id)
        resource, _ = await self._require_renderable(project.id, resource_id, principal.subject)

        definition = await self._tools.get_by_key(project.id, tool_key)
        if definition is not None and str(definition.integration_id) != str(resource.integration_id):
            raise AppOriginViolationError()

        if not self._limiter.check_and_hit(f"app:{resource.id}:{principal.subject.key}", BRIDGE_CALLS_PER_MINUTE):
            return InvocationResult(
                status=InvocationStatus.RATE_LIMITED, is_error=True, error_code="rate_limited",
                message="This app is making too many calls; retry shortly", retryable=True,
            )
        return await self._gateway.invoke(
            InvocationRequest(
                project_id=str(project.id), tool_key=tool_key, arguments=arguments,
                principal=dataclasses.replace(principal, origin="app_widget"), idempotency_key=idempotency_key,
            )
        )

    async def read_resource(self, project_id: IdLike, subject: Subject, resource_id: IdLike, uri: str) -> FetchedResource:
        """An approved app reads a resource its own integration lists or templates (FR-49)."""
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        resource, integration = await self._require_renderable(project.id, resource_id, subject)
        adapter = self._adapter(integration, ResourceReader)
        creds = await self._creds(integration, subject)
        try:
            listed = await adapter.list_resources(integration, creds)
            templates = await adapter.list_resource_templates(integration, creds)
            allowed = uri == resource.uri or any(r.uri == uri for r in listed) or any(template_matches(t.uri, uri) for t in templates)
            if not allowed:
                raise AppOriginViolationError("This resource is not exposed by the app's integration")
            return await adapter.read_resource(integration, creds, uri, READ_MAX_BYTES)
        except UpstreamError as exc:
            raise self._upstream(exc) from exc
