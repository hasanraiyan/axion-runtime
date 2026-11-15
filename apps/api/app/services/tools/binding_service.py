"""
BindingService (SRS-07 FR-30, Section 5.5): availability and audience rules (Gate 1 data).

End-user bindings are *deny-only* (a block list for named end users): an allow for one end
user could otherwise override an agent-level deny, which is a privilege-escalation path.
"""
from __future__ import annotations

from typing import List, Optional, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, NotFoundError
from app.core.protocols.tool_repositories import (
    IIntegrationRepository,
    IToolBindingRepository,
    IToolDefinitionRepository,
)
from app.core.tools.events import ToolsetChanged
from app.core.tools.ports import AuditPort, DomainEventPort
from app.models.project import ProjectAuditAction
from app.models.tool import (
    BindingEffect,
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
)
from app.schemas.tools import BindingReplaceRequest
from app.services.tools.common import ProjectLifecycle

IdLike = Union[str, PydanticObjectId, ObjectId]


class BindingService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        binding_repo: IToolBindingRepository,
        integration_repo: IIntegrationRepository,
        tool_repo: IToolDefinitionRepository,
        audit: AuditPort,
        events: DomainEventPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._bindings = binding_repo
        self._integrations = integration_repo
        self._tools = tool_repo
        self._audit = audit
        self._events = events

    async def list(
        self,
        project_id: IdLike,
        subject_type: Optional[BindingSubjectType] = None,
        subject_id: Optional[str] = None,
    ) -> List[ToolBinding]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        return await self._bindings.list_by_project(project.id, subject_type=subject_type, subject_id=subject_id)

    async def replace(self, project_id: IdLike, request: BindingReplaceRequest, actor_id: str) -> List[ToolBinding]:
        project = await self._lifecycle.get_active(project_id)

        if request.subject_type == BindingSubjectType.PROJECT_DEFAULT:
            if request.subject_id is not None:
                raise BadRequestError("project_default bindings must not name a subject")
        elif not request.subject_id:
            raise BadRequestError(f"{request.subject_type.value} bindings require a subject_id")

        seen: set[tuple[str, str]] = set()
        docs: List[ToolBinding] = []
        for rule in request.bindings:
            marker = (rule.target_type.value, rule.target_id)
            if marker in seen:
                raise BadRequestError(f"Duplicate rule for {rule.target_type.value} '{rule.target_id}'")
            seen.add(marker)

            if request.subject_type == BindingSubjectType.END_USER and rule.effect != BindingEffect.DENY:
                raise BadRequestError("End-user bindings can only deny; use agent or project bindings to allow")
            if rule.approval_policy_override is not None and rule.effect != BindingEffect.ALLOW:
                raise BadRequestError("approval_policy_override applies to allow rules only")

            if rule.target_type == BindingTargetType.INTEGRATION:
                integration = await self._integrations.get_by_id_and_project(rule.target_id, project.id)
                if integration is None:
                    raise NotFoundError(f"Integration '{rule.target_id}' not found")
            else:
                if await self._tools.get_by_key(project.id, rule.target_id) is None:
                    raise NotFoundError(f"Tool '{rule.target_id}' not found")

            docs.append(
                ToolBinding(
                    project_id=project.id,
                    subject_type=request.subject_type,
                    subject_id=request.subject_id,
                    audience=list(request.audience),
                    target_type=rule.target_type,
                    target_id=rule.target_id,
                    effect=rule.effect,
                    approval_policy_override=rule.approval_policy_override,
                    created_by=actor_id,
                )
            )

        saved = await self._bindings.replace_for_subject(project.id, request.subject_type, request.subject_id, docs)
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.BINDING_CREATED.value,
            {"subject_type": request.subject_type.value, "subject_id": request.subject_id, "rules": len(saved)},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "bindings_changed"))
        return saved
