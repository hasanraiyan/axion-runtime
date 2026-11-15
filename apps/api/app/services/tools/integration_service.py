"""
IntegrationService (SRS-07 FR-01..FR-08, FR-83): integration CRUD and lifecycle state only.

Single responsibility: it never runs discovery, talks OAuth, or executes tools. It validates
through the adapter and auth-strategy registries (never switching on type), checks secret
references and target URLs, and publishes domain events when the toolset may have changed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, NotFoundError
from app.core.outbound import OutboundUrlGuard
from app.core.protocols.repositories import ISecretRepository
from app.core.protocols.tool_repositories import IIntegrationRepository
from app.core.tools.events import McpSessionsInvalidated, ToolsetChanged
from app.core.tools.ports import AuditPort, DomainEventPort, IntegrationConnectionsPort
from app.core.tools.registry import AdapterRegistry, AuthStrategyRegistry, adapter_key
from app.models.integration import (
    AuthProfile,
    EndUserAccess,
    Integration,
    IntegrationStatus,
    IntegrationType,
    SharedIdentityAck,
)
from app.models.project import ProjectAuditAction
from app.schemas.tools import IntegrationCreateRequest, IntegrationUpdateRequest
from app.services.tools.common import ProjectLifecycle

IdLike = Union[str, PydanticObjectId, ObjectId]
SHARED_IDENTITY_TEXT_VERSION = "1"
SECRET_ENVIRONMENT = "production"


class IntegrationService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        secret_repo: ISecretRepository,
        adapters: AdapterRegistry,
        auth_registry: AuthStrategyRegistry,
        guard: OutboundUrlGuard,
        audit: AuditPort,
        events: DomainEventPort,
        connections: Optional[IntegrationConnectionsPort] = None,
    ) -> None:
        self._connections = connections
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._secrets = secret_repo
        self._adapters = adapters
        self._auth = auth_registry
        self._guard = guard
        self._audit = audit
        self._events = events

    # ------------------------------------------------------------------ validation
    async def _prepare(
        self, project_id: str, integration_type: IntegrationType, config: Dict[str, Any], profile: AuthProfile
    ) -> Tuple[Dict[str, Any], List[PydanticObjectId]]:
        adapter = self._adapters.get(adapter_key(integration_type, config))
        normalized = adapter.validate_config(dict(config))

        if profile.auth_type not in adapter.supported_auth_types():
            raise BadRequestError(f"Authentication type '{profile.auth_type.value}' is not supported by this integration type")
        strategy = self._auth.get(profile.auth_type)
        strategy.validate(profile)

        referenced: List[PydanticObjectId] = []
        for secret_id in strategy.secret_ids(profile):
            secret = await self._secrets.get_by_id_and_project(secret_id, project_id)
            if secret is None or secret.is_deleted:
                raise NotFoundError(f"Secret '{secret_id}' not found in project")
            referenced.append(secret.id)

        names = strategy.secret_names(profile)
        if names:
            found = await self._secrets.find_by_names(
                project_id=project_id, environment=SECRET_ENVIRONMENT, names=names, include_deleted=False
            )
            missing = sorted(set(names) - {s.name for s in found})
            if missing:
                raise BadRequestError(f"Secrets referenced by the configuration were not found: {', '.join(missing)}")
            referenced.extend(s.id for s in found)

        allowed = adapter.allowed_hosts(normalized)
        for url in adapter.target_urls(normalized):
            await self._guard.check(url, allowed_hosts=allowed)

        return normalized, referenced

    async def _get(self, project_id: IdLike, integration_id: IdLike, include_deleted: bool = False) -> Integration:
        integration = await self._integrations.get_by_id_and_project(
            integration_id, project_id, include_deleted=include_deleted
        )
        if integration is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        return integration

    # ---------------------------------------------------------------------- create
    async def create(self, project_id: IdLike, request: IntegrationCreateRequest, actor_id: str) -> Integration:
        project = await self._lifecycle.get_active(project_id)
        pid = str(project.id)
        normalized, referenced = await self._prepare(pid, request.type, request.config, request.auth_profile)

        existing = await self._integrations.get_by_slug(project.id, request.slug)
        if existing is not None:
            from app.core.exceptions import DuplicateIntegrationSlugError

            raise DuplicateIntegrationSlugError(request.slug)

        document = Integration(
            project_id=project.id,
            type=request.type,
            slug=request.slug,
            name=request.name,
            description=request.description,
            config=normalized,
            auth_profile=request.auth_profile,
            status=IntegrationStatus.DRAFT,
            referenced_secret_ids=referenced,
            created_by=actor_id,
            updated_by=actor_id,
        )
        created = await self._integrations.create(document)
        await self._audit.record(
            pid,
            actor_id,
            ProjectAuditAction.INTEGRATION_CREATED.value,
            {"integration_id": str(created.id), "slug": created.slug, "type": created.type.value},
        )
        return created

    # ------------------------------------------------------------------------ read
    async def get(self, project_id: IdLike, integration_id: IdLike) -> Integration:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        return await self._get(project.id, integration_id)

    async def list(
        self,
        project_id: IdLike,
        type: Optional[IntegrationType] = None,
        status: Optional[IntegrationStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Integration], int]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        return await self._integrations.list_by_project(
            project.id, type=type, status=status, search=search, skip=skip, limit=limit
        )

    # ---------------------------------------------------------------------- update
    async def update(
        self, project_id: IdLike, integration_id: IdLike, request: IntegrationUpdateRequest, actor_id: str
    ) -> Integration:
        project = await self._lifecycle.get_active(project_id)
        current = await self._get(project.id, integration_id)

        update: Dict[str, Any] = {"updated_by": actor_id}
        credentials_changed = False
        if request.name is not None:
            update["name"] = request.name
        if request.description is not None:
            update["description"] = request.description

        connection_changed = request.config is not None or request.auth_profile is not None
        if connection_changed:
            profile = request.auth_profile if request.auth_profile is not None else current.auth_profile
            config = request.config if request.config is not None else current.config
            normalized, referenced = await self._prepare(str(project.id), current.type, config, profile)
            update.update(
                config=normalized,
                auth_profile=profile,
                referenced_secret_ids=referenced,
                status=IntegrationStatus.DRAFT,
                status_reason="Connection settings changed; re-test required",
                consecutive_failures=0,
            )
            # Changing how an integration authenticates invalidates any prior shared-identity decision.
            if profile.auth_type != current.auth_profile.auth_type:
                update["end_user_access"] = EndUserAccess.CLOSED
                update["shared_identity_ack"] = None
            credentials_changed = (
                not profile.same_credentials_as(current.auth_profile)
                or normalized.get("url") != current.config.get("url")
            )

        updated = await self._integrations.update_with_revision(
            current.id, project.id, request.revision, update
        )
        if connection_changed and credentials_changed and self._connections is not None:
            # Existing connections were issued for different credentials or endpoints and must not survive.
            await self._connections.revoke_all(str(project.id), str(current.id), actor_id, "credentials_changed")
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.INTEGRATION_UPDATED.value,
            {"integration_id": str(updated.id), "fields": sorted(k for k in update if k != "updated_by")},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "integration_updated"))
        if connection_changed:
            await self._events.publish(McpSessionsInvalidated(str(project.id), str(updated.id), "connection_changed"))
        return updated

    # --------------------------------------------------------------- enable/disable
    async def set_enabled(self, project_id: IdLike, integration_id: IdLike, enabled: bool, actor_id: str) -> Integration:
        project = await self._lifecycle.get_active(project_id)
        current = await self._get(project.id, integration_id)
        if enabled:
            status = IntegrationStatus.ACTIVE if current.last_discovery_at else IntegrationStatus.DRAFT
        else:
            status = IntegrationStatus.DISABLED
        updated = await self._integrations.update_with_revision(
            current.id,
            project.id,
            current.revision,
            {"is_enabled": enabled, "status": status, "status_reason": None, "updated_by": actor_id},
        )
        await self._audit.record(
            str(project.id),
            actor_id,
            (ProjectAuditAction.INTEGRATION_ENABLED if enabled else ProjectAuditAction.INTEGRATION_DISABLED).value,
            {"integration_id": str(updated.id)},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "integration_toggled"))
        if not enabled:
            await self._events.publish(McpSessionsInvalidated(str(project.id), str(updated.id), "disabled"))
        return updated

    # ----------------------------------------------------------------- soft delete
    async def delete(self, project_id: IdLike, integration_id: IdLike, actor_id: str) -> Integration:
        project = await self._lifecycle.get_active(project_id)
        current = await self._get(project.id, integration_id)
        updated = await self._integrations.update_with_revision(
            current.id,
            project.id,
            current.revision,
            {
                "is_deleted": True,
                "deleted_at": datetime.now(timezone.utc),
                "is_enabled": False,
                "updated_by": actor_id,
            },
        )
        if self._connections is not None:
            await self._connections.revoke_all(str(project.id), str(updated.id), actor_id, "integration_deleted")
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.INTEGRATION_DELETED.value, {"integration_id": str(updated.id)}
        )
        await self._events.publish(ToolsetChanged(str(project.id), "integration_deleted"))
        await self._events.publish(McpSessionsInvalidated(str(project.id), str(updated.id), "deleted"))
        return updated

    async def restore(self, project_id: IdLike, integration_id: IdLike, actor_id: str) -> Integration:
        project = await self._lifecycle.get_active(project_id)
        current = await self._get(project.id, integration_id, include_deleted=True)
        if not current.is_deleted:
            from app.core.exceptions import IntegrationStateError

            raise IntegrationStateError("Integration is not deleted")
        updated = await self._integrations.update_with_revision(
            current.id,
            project.id,
            current.revision,
            {
                "is_deleted": False,
                "deleted_at": None,
                "is_enabled": True,
                "status": IntegrationStatus.DRAFT,
                "status_reason": "Restored; re-test required",
                "updated_by": actor_id,
            },
            include_deleted=True,
        )
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.INTEGRATION_RESTORED.value, {"integration_id": str(updated.id)}
        )
        await self._events.publish(ToolsetChanged(str(project.id), "integration_restored"))
        return updated

    # ---------------------------------------------------------- end-user access
    async def set_end_user_access(
        self,
        project_id: IdLike,
        integration_id: IdLike,
        access: EndUserAccess,
        acknowledge_shared_identity: bool,
        actor_id: str,
    ) -> Integration:
        """
        Open or close an integration to end users (FR-83).

        Every ``project_shared`` integration makes end users act through the project's own
        identity or capabilities, so opening one needs an explicit acknowledgment. This applies
        uniformly; there is deliberately no per-type special case.
        """
        from app.models.integration import CredentialMode

        project = await self._lifecycle.get_active(project_id)
        current = await self._get(project.id, integration_id)

        update: Dict[str, Any] = {"end_user_access": access, "updated_by": actor_id}
        if access == EndUserAccess.OPEN and current.auth_profile.credential_mode == CredentialMode.PROJECT_SHARED:
            if not acknowledge_shared_identity:
                err = BadRequestError(
                    "End users would act with the project's shared identity; set acknowledge_shared_identity to proceed"
                )
                err.code = "SHARED_IDENTITY_ACK_REQUIRED"
                raise err
            update["shared_identity_ack"] = SharedIdentityAck(
                acknowledged_by=actor_id,
                acknowledged_at=datetime.now(timezone.utc),
                text_version=SHARED_IDENTITY_TEXT_VERSION,
            )
        updated = await self._integrations.update_with_revision(current.id, project.id, current.revision, update)
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.INTEGRATION_END_USER_ACCESS_CHANGED.value,
            {
                "integration_id": str(updated.id),
                "access": access.value,
                "shared_identity_acknowledged": bool(update.get("shared_identity_ack")),
            },
        )
        await self._events.publish(ToolsetChanged(str(project.id), "end_user_access_changed"))
        return updated

    # ------------------------------------------------------------- secret guard
    async def integrations_referencing_secret(self, project_id: IdLike, secret_id: IdLike) -> List[str]:
        """Names of live integrations that reference a secret (supports the FR-08 deletion guard)."""
        return [i.name for i in await self._integrations.find_referencing_secret(project_id, secret_id)]
