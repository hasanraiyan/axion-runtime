"""
ToolsetResolver (SRS-07 FR-31): joins definitions, settings, bindings, and integrations into the
access-filtered toolset a principal may use, plus a report of what was excluded and why.

Read-only and network-free (no discovery, no upstream calls). ``resolve_one`` serves the Gateway so
that listing and invoking share exactly the same availability logic.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.protocols.tool_repositories import (
    IIntegrationRepository,
    IToolBindingRepository,
    IToolDefinitionRepository,
    IToolSettingRepository,
)
from app.core.tools.policy import default_approval_policy
from app.core.tools.registry import AdapterRegistry
from app.core.tools.types import PrincipalContext, ResolvedTool, SubjectType
from app.models.integration import Integration
from app.models.tool import ToolBinding, ToolDefinition, ToolSetting
from app.services.tools.access import Availability, ToolAccessService
from app.services.tools.common import ProjectLifecycle

DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 300


@dataclass
class Exclusion:
    reason: str
    tool_key: Optional[str] = None
    integration: Optional[str] = None


@dataclass
class AuthRequiredInfo:
    integration_id: str
    integration: str
    reason: str = "connection_required"
    connect_available: bool = False


@dataclass
class Toolset:
    version: str
    tools: List[ResolvedTool] = field(default_factory=list)
    excluded: List[Exclusion] = field(default_factory=list)
    auth_required: List[AuthRequiredInfo] = field(default_factory=list)


@dataclass
class ToolContext:
    tool: ResolvedTool
    integration: Integration
    definition: ToolDefinition
    setting: ToolSetting
    availability: Availability


def visible_schema(schema: Dict[str, Any], hidden: set[str]) -> Dict[str, Any]:
    """Schema shown to the model: locked and context-bound parameters are removed (FR-15, FR-76)."""
    result = copy.deepcopy(schema or {"type": "object", "properties": {}})
    props = result.get("properties")
    if isinstance(props, dict):
        for name in hidden:
            props.pop(name, None)
    if isinstance(result.get("required"), list):
        result["required"] = [r for r in result["required"] if r not in hidden]
        if not result["required"]:
            result.pop("required")
    return result


class ToolsetResolver:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        tool_repo: IToolDefinitionRepository,
        setting_repo: IToolSettingRepository,
        binding_repo: IToolBindingRepository,
        adapters: AdapterRegistry,
        access: Optional[ToolAccessService] = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._tools = tool_repo
        self._settings = setting_repo
        self._bindings = binding_repo
        self._adapters = adapters
        self._access = access or ToolAccessService()

    # ------------------------------------------------------------------- helpers
    def _build(
        self,
        integration: Integration,
        definition: ToolDefinition,
        setting: ToolSetting,
        availability: Availability,
        principal: PrincipalContext,
    ) -> ResolvedTool:
        hidden = set(setting.locked_arguments) | set(setting.context_arguments)
        description = setting.description_override or definition.description
        timeout = min(setting.timeout_seconds or DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)
        ui = definition.ui.model_dump(mode="json") if definition.ui else None
        return ResolvedTool(
            tool_key=definition.tool_key,
            integration_id=str(integration.id),
            integration_slug=integration.slug,
            integration_type=integration.type.value,
            upstream_name=definition.upstream_name,
            description=description,
            input_schema=definition.input_schema,
            annotations=definition.annotations.model_dump(),
            approval_policy=availability.approval_policy.value,
            timeout_seconds=timeout,
            ui=ui,
            config=integration.config,
            visible_schema=visible_schema(definition.input_schema, hidden),
            definition_hash=definition.definition_hash,
            locked_arguments=dict(setting.locked_arguments),
            default_arguments=dict(setting.default_arguments),
            context_arguments=dict(setting.context_arguments),
            rate_limit_per_minute=setting.rate_limit_per_minute,
            per_end_user_rate_limit_per_minute=setting.per_end_user_rate_limit_per_minute,
            ui_visibility=ui["visibility"] if ui else None,
        )

    @staticmethod
    def _version(principal: PrincipalContext, tools: List[ResolvedTool], settings: List[ToolSetting], bindings: List[ToolBinding]) -> str:
        payload = {
            "subject": principal.subject.key,
            "agent": principal.agent_id,
            "tools": sorted((t.tool_key, t.definition_hash) for t in tools),
            "settings": sorted((s.tool_key, s.revision) for s in settings),
            "bindings": sorted((str(b.id), b.revision) for b in bindings),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:32]

    # ------------------------------------------------------------------- toolset
    async def resolve_toolset(self, principal: PrincipalContext, agent_id: Optional[str] = None) -> Toolset:
        project = await self._lifecycle.get_active(principal.project_id)
        end_user_external = principal.subject.external_id if principal.subject.type == SubjectType.END_USER else None
        bindings = await self._bindings.list_for_resolution(project.id, principal.agent_id, end_user_external)

        integrations, _ = await self._integrations.list_by_project(project.id, limit=1000)
        by_id = {str(i.id): i for i in integrations}
        definitions, _ = await self._tools.list_by_project(project.id, limit=5000)
        settings = {s.tool_key: s for s in await self._settings.list_by_keys(project.id, [d.tool_key for d in definitions])}

        toolset = Toolset(version="")
        auth_seen: set[str] = set()
        for definition in definitions:
            integration = by_id.get(str(definition.integration_id))
            if integration is None:
                continue  # deleted integration: nothing to report
            setting = settings.get(definition.tool_key)
            availability = self._access.evaluate(integration, definition, setting, bindings, principal)
            if availability.available and setting is not None:
                if definition.ui and "model" not in definition.ui.visibility:
                    continue  # app-only tools never enter an agent toolset (FR-45)
                toolset.tools.append(self._build(integration, definition, setting, availability, principal))
            elif availability.auth_required:
                if str(integration.id) not in auth_seen:
                    auth_seen.add(str(integration.id))
                    toolset.auth_required.append(AuthRequiredInfo(str(integration.id), integration.slug))
            elif availability.reason in {"disabled", "not_bound"} and setting is not None and not setting.is_enabled:
                continue  # silently omit tools an admin has not enabled; they are not "excluded", just off
            else:
                toolset.excluded.append(Exclusion(availability.reason or "unavailable", tool_key=definition.tool_key))

        toolset.version = self._version(principal, toolset.tools, list(settings.values()), bindings)
        return toolset

    # ------------------------------------------------------------------- single
    async def resolve_one(self, principal: PrincipalContext, tool_key: str) -> Optional[ToolContext]:
        """Resolve one tool with its availability; ``None`` if no such tool exists in the project."""
        project = await self._lifecycle.get_active(principal.project_id)
        definition = await self._tools.get_by_key(project.id, tool_key)
        if definition is None:
            return None
        integration = await self._integrations.get_by_id_and_project(definition.integration_id, project.id)
        if integration is None:
            return None
        setting = await self._settings.get_by_key(project.id, tool_key)
        end_user_external = principal.subject.external_id if principal.subject.type == SubjectType.END_USER else None
        bindings = await self._bindings.list_for_resolution(project.id, principal.agent_id, end_user_external)
        availability = self._access.evaluate(integration, definition, setting, bindings, principal)
        effective_setting = setting or ToolSetting(
            project_id=project.id,
            tool_key=tool_key,
            approval_policy=default_approval_policy(definition.annotations.model_dump()),
        )
        tool = self._build(integration, definition, effective_setting, availability, principal)
        return ToolContext(tool, integration, definition, effective_setting, availability)
