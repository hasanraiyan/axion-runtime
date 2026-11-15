"""
ToolCascadePurger (SRS-07 FR-07): removes all Module 07 data when a project is purged.

Separate from ``IntegrationService`` (single responsibility). Order: invocations, bindings, settings,
tools, end users, integrations. Standalone MongoDB has no transactions (AGENTS invariant 8), so each
step is idempotent and a retry completes whatever a partial failure left behind.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.protocols.tool_repositories import (
    IEndUserRepository,
    IIntegrationRepository,
    IToolBindingRepository,
    IToolDefinitionRepository,
    IToolInvocationRepository,
    IToolSettingRepository,
)
from app.core.tools.ports import AuditPort
from app.models.project import ProjectAuditAction

IdLike = Union[str, PydanticObjectId, ObjectId]


class ToolCascadePurger:
    def __init__(
        self,
        invocation_repo: IToolInvocationRepository,
        binding_repo: IToolBindingRepository,
        setting_repo: IToolSettingRepository,
        tool_repo: IToolDefinitionRepository,
        end_user_repo: IEndUserRepository,
        integration_repo: IIntegrationRepository,
        audit: AuditPort,
        connection_repo: Optional[Any] = None,
        session_repo: Optional[Any] = None,
        oauth_client_repo: Optional[Any] = None,
        policy_repo: Optional[Any] = None,
        app_repo: Optional[Any] = None,
    ) -> None:
        extra = tuple(
            (label, repo)
            for label, repo in (
                ("connections", connection_repo),
                ("connect_sessions", session_repo),
                ("oauth_clients", oauth_client_repo),
                ("policies", policy_repo),
                ("app_resources", app_repo),
            )
            if repo is not None
        )
        self._steps = extra + (
            ("invocations", invocation_repo),
            ("bindings", binding_repo),
            ("settings", setting_repo),
            ("tools", tool_repo),
            ("end_users", end_user_repo),
            ("integrations", integration_repo),
        )
        self._audit = audit

    async def purge_project(self, project_id: IdLike, actor_id: str = "system") -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for label, repo in self._steps:
            counts[label] = await repo.delete_by_project_id(project_id)
        if counts.get("integrations"):
            await self._audit.record(
                str(project_id), actor_id, ProjectAuditAction.INTEGRATION_PURGED.value, counts
            )
        return counts
