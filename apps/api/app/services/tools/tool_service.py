"""
ToolCatalogService (reads) and ToolSettingService (admin writes) (SRS-07 FR-13..FR-16).

Split by writer: discovery owns ``ToolDefinition``; this module owns ``ToolSetting`` only,
plus the approval act that records the approved hash.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from beanie import PydanticObjectId
from bson import ObjectId
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from app.core.exceptions import BadRequestError, NotFoundError, RevisionConflictError, ToolDriftPendingError
from app.core.protocols.tool_repositories import IToolDefinitionRepository, IToolSettingRepository
from app.core.tools.context import is_valid_context_key
from app.core.tools.events import ToolsetChanged
from app.core.tools.policy import default_approval_policy
from app.core.tools.ports import AuditPort, DomainEventPort
from app.models.project import ProjectAuditAction
from app.models.tool import ToolDefinition, ToolSetting, ToolSyncState
from app.schemas.tools import ToolBulkAction, ToolBulkItemResult, ToolBulkRequest, ToolBulkResponse, ToolSettingUpdateRequest
from app.services.tools.common import ProjectLifecycle

IdLike = Union[str, PydanticObjectId, ObjectId]


def _default_setting(project_id: Any, definition: ToolDefinition) -> ToolSetting:
    """In-memory default for a tool that has no stored setting (never persisted by reads)."""
    return ToolSetting(
        project_id=project_id,
        tool_key=definition.tool_key,
        approval_policy=default_approval_policy(definition.annotations.model_dump()),
    )


class ToolCatalogService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        tool_repo: IToolDefinitionRepository,
        setting_repo: IToolSettingRepository,
    ) -> None:
        self._lifecycle = lifecycle
        self._tools = tool_repo
        self._settings = setting_repo

    async def list_tools(
        self,
        project_id: IdLike,
        integration_id: Optional[IdLike] = None,
        sync_state: Optional[ToolSyncState] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Tuple[ToolDefinition, ToolSetting]], int]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        definitions, total = await self._tools.list_by_project(
            project.id, integration_id=integration_id, sync_state=sync_state, search=search, skip=skip, limit=limit
        )
        settings = {s.tool_key: s for s in await self._settings.list_by_keys(project.id, [d.tool_key for d in definitions])}
        return [(d, settings.get(d.tool_key) or _default_setting(project.id, d)) for d in definitions], total

    async def get_tool(self, project_id: IdLike, tool_key: str) -> Tuple[ToolDefinition, ToolSetting]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        definition = await self._tools.get_by_key(project.id, tool_key)
        if definition is None:
            raise NotFoundError(f"Tool '{tool_key}' not found")
        setting = await self._settings.get_by_key(project.id, tool_key)
        return definition, setting or _default_setting(project.id, definition)


class ToolSettingService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        tool_repo: IToolDefinitionRepository,
        setting_repo: IToolSettingRepository,
        audit: AuditPort,
        events: DomainEventPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._tools = tool_repo
        self._settings = setting_repo
        self._audit = audit
        self._events = events

    @staticmethod
    def _validate_arguments(definition: ToolDefinition, request: ToolSettingUpdateRequest, current: ToolSetting) -> None:
        schema = definition.input_schema or {}
        properties: Dict[str, Any] = schema.get("properties") or {}
        locked = request.locked_arguments if request.locked_arguments is not None else current.locked_arguments
        defaults = request.default_arguments if request.default_arguments is not None else current.default_arguments
        context = request.context_arguments if request.context_arguments is not None else current.context_arguments

        for label, mapping in (("locked_arguments", locked), ("default_arguments", defaults), ("context_arguments", context)):
            for name in mapping:
                if name not in properties:
                    raise BadRequestError(f"{label}: '{name}' is not a parameter of this tool")
        overlap = (set(locked) & set(context)) | (set(locked) & set(defaults)) | (set(context) & set(defaults))
        if overlap:
            raise BadRequestError(f"A parameter can be locked, defaulted, or context-bound, not several: {sorted(overlap)[0]}")
        for name, key in context.items():
            if not is_valid_context_key(key):
                raise BadRequestError(f"context_arguments: '{key}' is not a supported context key")
        for label, mapping in (("locked_arguments", locked), ("default_arguments", defaults)):
            for name, value in mapping.items():
                try:
                    errors = list(Draft202012Validator(properties[name]).iter_errors(value))
                except SchemaError:
                    continue  # an unusable upstream sub-schema cannot reject an admin value
                if errors:
                    raise BadRequestError(f"{label}: value for '{name}' is invalid: {errors[0].message[:200]}")

    async def update(
        self, project_id: IdLike, tool_key: str, request: ToolSettingUpdateRequest, actor_id: str
    ) -> Tuple[ToolDefinition, ToolSetting]:
        project = await self._lifecycle.get_active(project_id)
        definition = await self._tools.get_by_key(project.id, tool_key)
        if definition is None:
            raise NotFoundError(f"Tool '{tool_key}' not found")
        current = await self._settings.get_or_create_default(
            project.id, tool_key, {"approval_policy": default_approval_policy(definition.annotations.model_dump())}
        )
        self._validate_arguments(definition, request, current)

        update: Dict[str, Any] = {"updated_by": actor_id}
        for name in (
            "approval_policy",
            "description_override",
            "locked_arguments",
            "default_arguments",
            "context_arguments",
            "timeout_seconds",
            "rate_limit_per_minute",
            "per_end_user_rate_limit_per_minute",
        ):
            value = getattr(request, name)
            if value is not None:
                update[name] = value

        if request.is_enabled is not None:
            if request.is_enabled:
                if definition.sync_state == ToolSyncState.CHANGED:
                    raise ToolDriftPendingError(tool_key)
                if definition.sync_state == ToolSyncState.REMOVED_UPSTREAM:
                    raise BadRequestError("This tool no longer exists upstream and cannot be enabled")
                update["approved_hash"] = definition.definition_hash  # enabling is the admin's approval
            update["is_enabled"] = request.is_enabled

        updated = await self._settings.update_with_revision(project.id, tool_key, request.revision, update)
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.TOOL_UPDATED.value,
            {"tool_key": tool_key, "fields": sorted(k for k in update if k != "updated_by")},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "tool_updated"))
        return definition, updated

    async def approve(self, project_id: IdLike, tool_key: str, actor_id: str) -> Tuple[ToolDefinition, ToolSetting]:
        """Record approval of the tool's current definition (FR-16); returns it to ``in_sync``."""
        project = await self._lifecycle.get_active(project_id)
        definition = await self._tools.get_by_key(project.id, tool_key)
        if definition is None:
            raise NotFoundError(f"Tool '{tool_key}' not found")
        if definition.sync_state == ToolSyncState.REMOVED_UPSTREAM:
            raise BadRequestError("This tool no longer exists upstream")
        setting = await self._settings.get_or_create_default(
            project.id, tool_key, {"approval_policy": default_approval_policy(definition.annotations.model_dump())}
        )
        updated = await self._settings.update_with_revision(
            project.id, tool_key, setting.revision, {"approved_hash": definition.definition_hash, "updated_by": actor_id}
        )
        if definition.sync_state == ToolSyncState.CHANGED:
            definition = await self._tools.update_definition(
                definition.id, definition.revision, {"sync_state": ToolSyncState.IN_SYNC}
            )
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.TOOL_APPROVED.value,
            {"tool_key": tool_key, "definition_hash": definition.definition_hash},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "tool_approved"))
        return definition, updated


    # ----------------------------------------------------------------------- bulk
    async def bulk_update(self, project_id: IdLike, request: ToolBulkRequest, actor_id: str) -> ToolBulkResponse:
        """
        Apply one action to many tools. There are no transactions on standalone MongoDB (AGENTS invariant 8), so the
        outcome is reported per tool: a conflict or a drifted tool never aborts the rest and is never silently
        approved. Enabling a tool still means approving its *current* definition, exactly as a single update does.
        """
        project = await self._lifecycle.get_active(project_id)
        results: List[ToolBulkItemResult] = []

        if request.tool_keys:
            keys = list(dict.fromkeys(request.tool_keys))
            found = {d.tool_key: d for d in await self._tools.list_by_keys(project.id, keys)}
            selection: List[Tuple[str, Optional[ToolDefinition]]] = [(k, found.get(k)) for k in keys]
        else:
            definitions = [
                d for d in await self._tools.list_by_integration(request.integration_id)  # type: ignore[arg-type]
                if str(d.project_id) == str(project.id)  # never cross a tenant boundary
            ]
            if request.read_only_only:
                definitions = [d for d in definitions if d.annotations.read_only is True and d.annotations.destructive is not True]
            selection = [(d.tool_key, d) for d in sorted(definitions, key=lambda d: d.tool_key)]

        for key, definition in selection:
            if definition is None:
                results.append(ToolBulkItemResult(tool_key=key, outcome="failed", reason="not_found"))
                continue
            results.append(await self._bulk_one(project.id, definition, request, actor_id))

        response = ToolBulkResponse(
            updated=sum(r.outcome == "updated" for r in results),
            skipped=sum(r.outcome == "skipped" for r in results),
            failed=sum(r.outcome == "failed" for r in results),
            results=results,
        )
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.TOOL_BULK_UPDATED.value,
            {"action": request.action.value, "updated": response.updated, "skipped": response.skipped, "failed": response.failed},
        )
        if response.updated:
            await self._events.publish(ToolsetChanged(str(project.id), "tools_bulk_updated"))
        return response

    async def _bulk_one(self, project_id: Any, definition: ToolDefinition, request: ToolBulkRequest, actor_id: str) -> ToolBulkItemResult:
        key = definition.tool_key
        setting = await self._settings.get_or_create_default(
            project_id, key, {"approval_policy": default_approval_policy(definition.annotations.model_dump())}
        )
        fields: Dict[str, Any] = {"updated_by": actor_id}
        if request.action == ToolBulkAction.ENABLE:
            if definition.sync_state == ToolSyncState.CHANGED:
                return ToolBulkItemResult(tool_key=key, outcome="skipped", reason="drift_pending")
            if definition.sync_state == ToolSyncState.REMOVED_UPSTREAM:
                return ToolBulkItemResult(tool_key=key, outcome="skipped", reason="removed_upstream")
            if setting.is_enabled and setting.approved_hash == definition.definition_hash:
                return ToolBulkItemResult(tool_key=key, outcome="skipped", reason="already_enabled")
            fields.update(is_enabled=True, approved_hash=definition.definition_hash)
        elif request.action == ToolBulkAction.DISABLE:
            if not setting.is_enabled:
                return ToolBulkItemResult(tool_key=key, outcome="skipped", reason="already_disabled")
            fields["is_enabled"] = False
        else:
            if setting.approval_policy == request.approval_policy:
                return ToolBulkItemResult(tool_key=key, outcome="skipped", reason="unchanged")
            fields["approval_policy"] = request.approval_policy
        try:
            await self._settings.update_with_revision(project_id, key, setting.revision, fields)
        except RevisionConflictError:
            return ToolBulkItemResult(tool_key=key, outcome="failed", reason="conflict")
        return ToolBulkItemResult(tool_key=key, outcome="updated")
