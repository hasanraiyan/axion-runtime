"""
DiscoveryService (SRS-07 FR-10, FR-11, FR-13, FR-16): the only writer of ``ToolDefinition``.

Discovery is an explicit, audited operation; the runtime never calls it (FR-50). It diffs a
provider's catalog against stored definitions and applies drift rules: a changed, previously
approved definition is suspended (``changed``) until an admin re-approves it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, NotFoundError, UpstreamFailureError
from app.core.protocols.tool_repositories import (
    IIntegrationRepository,
    IToolDefinitionRepository,
    IToolSettingRepository,
)
from app.core.tools.errors import UpstreamAuthError, UpstreamError
from app.core.tools.events import ToolsetChanged
from app.core.tools.hashing import catalog_hash, definition_hash, make_tool_key
from app.core.tools.policy import default_approval_policy
from app.core.tools.ports import AuditPort, DomainEventPort, ToolDiscoverer, supports
from app.core.tools.registry import AdapterRegistry
from app.core.tools.types import DiscoveredTool, Subject, SubjectType
from app.models.integration import IntegrationStatus
from app.models.project import ProjectAuditAction
from app.models.tool import ToolAnnotations, ToolDefinition, ToolSyncState, ToolUi
from app.services.tools.common import ProjectLifecycle
from app.services.tools.credentials import AuthRequired, CredentialBuilder

IdLike = Union[str, PydanticObjectId, ObjectId]


@dataclass
class DiscoverySummary:
    added: List[str] = field(default_factory=list)
    changed: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    unchanged: int = 0
    total: int = 0
    catalog_hash: str = ""


def _annotations(raw: Dict[str, Optional[bool]]) -> ToolAnnotations:
    return ToolAnnotations(**{k: v for k, v in raw.items() if k in ToolAnnotations.model_fields})


class DiscoveryService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        tool_repo: IToolDefinitionRepository,
        setting_repo: IToolSettingRepository,
        adapters: AdapterRegistry,
        credentials: CredentialBuilder,
        audit: AuditPort,
        events: DomainEventPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._tools = tool_repo
        self._settings = setting_repo
        self._adapters = adapters
        self._credentials = credentials
        self._audit = audit
        self._events = events

    async def discover(self, project_id: IdLike, integration_id: IdLike, actor_id: str) -> DiscoverySummary:
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integrations.get_by_id_and_project(integration_id, project.id)
        if integration is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        adapter = self._adapters.for_integration(integration)
        if not supports(adapter, ToolDiscoverer):
            raise BadRequestError("This integration type does not support tool discovery")

        try:
            credentials = await self._credentials.resolve(integration, Subject(SubjectType.PROJECT))
        except AuthRequired:
            raise BadRequestError(
                "Per-user integrations are discovered with a connected user's credentials, which are not available yet"
            ) from None

        try:
            discovered = await adapter.discover(integration, credentials)
        except UpstreamAuthError as exc:
            await self._fail(integration, "Upstream rejected the credentials")
            raise UpstreamFailureError("The upstream rejected the credentials", code="UPSTREAM_AUTH_FAILED") from exc
        except UpstreamError as exc:
            await self._fail(integration, str(exc))
            raise UpstreamFailureError(f"Discovery failed: {str(exc)[:200]}") from exc

        summary = await self._apply(project.id, integration, discovered)

        new_status = integration.status if integration.status == IntegrationStatus.DISABLED else IntegrationStatus.ACTIVE
        await self._integrations.update_runtime_state(
            integration.id,
            project.id,
            {
                "last_discovery_at": datetime.now(timezone.utc),
                "catalog_hash": summary.catalog_hash,
                "status": new_status,
                "status_reason": None,
                "consecutive_failures": 0,
            },
        )
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.INTEGRATION_DISCOVERED.value,
            {
                "integration_id": str(integration.id),
                "added": len(summary.added),
                "changed": len(summary.changed),
                "removed": len(summary.removed),
                "total": summary.total,
            },
        )
        if summary.changed:
            await self._audit.record(
                str(project.id),
                actor_id,
                ProjectAuditAction.TOOL_DRIFT_DETECTED.value,
                {"integration_id": str(integration.id), "tools": summary.changed},
            )
        await self._events.publish(ToolsetChanged(str(project.id), "discovery"))
        return summary

    async def _fail(self, integration, reason: str) -> None:
        await self._integrations.update_runtime_state(
            integration.id,
            integration.project_id,
            {"status": IntegrationStatus.ERROR, "status_reason": reason[:500]},
        )

    async def _apply(self, project_id, integration, discovered: List[DiscoveredTool]) -> DiscoverySummary:
        summary = DiscoverySummary()
        existing = {d.upstream_name: d for d in await self._tools.list_by_integration(integration.id)}
        used_keys = {d.tool_key for d in existing.values()}
        seen_names: set[str] = set()
        new_docs: List[ToolDefinition] = []
        hashes: List[str] = []
        now = datetime.now(timezone.utc)

        for tool in discovered:
            if tool.name in seen_names:
                continue  # a provider listing the same name twice is ignored after the first
            seen_names.add(tool.name)
            digest = definition_hash(tool)
            hashes.append(digest)
            current = existing.get(tool.name)

            if current is None:
                key = make_tool_key(integration.slug, tool.name)
                base, n = key, 2
                while key in used_keys:
                    key = f"{base}_{n}"
                    n += 1
                used_keys.add(key)
                doc = ToolDefinition(
                    project_id=project_id,
                    integration_id=integration.id,
                    tool_key=key,
                    upstream_name=tool.name,
                    title=tool.title,
                    description=tool.description,
                    input_schema=tool.input_schema,
                    output_schema=tool.output_schema,
                    annotations=_annotations(tool.annotations),
                    ui=ToolUi(**tool.ui) if tool.ui else None,
                    definition_hash=digest,
                    sync_state=ToolSyncState.IN_SYNC,
                )
                new_docs.append(doc)
                await self._settings.get_or_create_default(
                    project_id,
                    key,
                    {
                        "approval_policy": default_approval_policy(tool.annotations),
                        "is_enabled": tool.default_enabled,
                        "approved_hash": digest if tool.default_enabled else None,
                    },
                )
                summary.added.append(key)
                continue

            setting = await self._settings.get_by_key(project_id, current.tool_key)
            approved = setting.approved_hash if setting else None

            if digest == current.definition_hash:
                target = current.sync_state
                if current.sync_state == ToolSyncState.REMOVED_UPSTREAM:
                    target = ToolSyncState.IN_SYNC if approved in (None, digest) else ToolSyncState.CHANGED
                if target != current.sync_state:
                    await self._tools.set_sync_state([current.id], target)
                    if target == ToolSyncState.CHANGED:
                        summary.changed.append(current.tool_key)
                else:
                    summary.unchanged += 1
                continue

            # Definition changed upstream.
            if approved is None or approved == digest:
                state = ToolSyncState.IN_SYNC  # never approved (still disabled) or changed back to approved
            else:
                state = ToolSyncState.CHANGED  # suspended until an admin re-approves (FR-16)
            await self._tools.update_definition(
                current.id,
                current.revision,
                {
                    "title": tool.title,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "output_schema": tool.output_schema,
                    "annotations": _annotations(tool.annotations),
                    "ui": ToolUi(**tool.ui) if tool.ui else None,
                    "definition_hash": digest,
                    "sync_state": state,
                    "last_seen_at": now,
                },
            )
            if state == ToolSyncState.CHANGED:
                summary.changed.append(current.tool_key)
            else:
                summary.unchanged += 1

        if new_docs:
            await self._tools.create_many(new_docs)

        gone = [
            d
            for name, d in existing.items()
            if name not in seen_names
            and d.sync_state not in (ToolSyncState.MANUAL, ToolSyncState.REMOVED_UPSTREAM)
        ]
        if gone:
            await self._tools.set_sync_state([d.id for d in gone], ToolSyncState.REMOVED_UPSTREAM)
            summary.removed.extend(d.tool_key for d in gone)

        summary.total = len(seen_names)
        summary.catalog_hash = catalog_hash(hashes)
        return summary
