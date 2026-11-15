"""
PrincipalResolver and ApprovalService.

``PrincipalResolver`` is the only place that turns an authenticated HTTP actor into the
``PrincipalContext`` (actor and subject) the Gateway uses. The subject is derived from the
authenticated actor; it is never taken from model output or tool arguments (FR-75).
"""
from __future__ import annotations

from typing import List, Optional

from app.core.exceptions import BadRequestError, ForbiddenError
from app.core.tools.ports import AuditPort
from app.core.tools.signing import TokenSigner, arguments_hash
from app.core.tools.types import Actor, ActorType, PrincipalContext, Subject, SubjectType
from app.models.project import Project, ProjectAuditAction, ProjectRole
from app.schemas.auth import AuthenticatedActor
from app.services.tools.end_user_service import EndUserService
from app.services.tools.gateway_stages import APPROVAL_PURPOSE

_ROLE_ORDER = {ProjectRole.VIEWER: 1, ProjectRole.MEMBER: 2, ProjectRole.ADMIN: 3, ProjectRole.OWNER: 4}


def role_at_least(role: Optional[ProjectRole], minimum: ProjectRole) -> bool:
    return role is not None and _ROLE_ORDER[role] >= _ROLE_ORDER[minimum]


def has_scope(scopes: List[str], scope: str) -> bool:
    return "*" in scopes or scope in scopes


class PrincipalResolver:
    def __init__(self, end_users: EndUserService) -> None:
        self._end_users = end_users

    async def resolve(
        self,
        actor: AuthenticatedActor,
        project: Project,
        project_role: Optional[ProjectRole],
        *,
        end_user_external_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        run_id: Optional[str] = None,
        request_id: Optional[str] = None,
        min_member_role: ProjectRole = ProjectRole.MEMBER,
    ) -> PrincipalContext:
        if actor.actor_type == "credential":
            if end_user_external_id:
                if not has_scope(actor.scopes, "end_users:assert"):
                    raise ForbiddenError("This credential cannot act for end users (missing scope end_users:assert)")
                subject = await self._end_users.resolve_subject(project.id, end_user_external_id, actor.identity_id)
            else:
                subject = Subject(SubjectType.PROJECT)
            return PrincipalContext(
                project_id=str(project.id),
                actor=Actor(ActorType.MACHINE, actor.identity_id),
                subject=subject,
                agent_id=agent_id,
                run_id=run_id,
                origin="runtime",
                request_id=request_id,
            )

        if end_user_external_id:
            raise BadRequestError("Project members cannot act as end users")
        if not role_at_least(project_role, min_member_role):
            raise ForbiddenError("Insufficient project permissions")
        return PrincipalContext(
            project_id=str(project.id),
            actor=Actor(ActorType.USER, actor.identity_id),
            subject=Subject(SubjectType.MEMBER, id=actor.identity_id),
            agent_id=agent_id,
            run_id=run_id,
            origin="playground",
            request_id=request_id,
            member_role=project_role.value if project_role else None,
        )


class ApprovalService:
    """Issues approval tokens bound to one exact call (SRS-07 FR-37)."""

    def __init__(self, signer: TokenSigner, end_users: EndUserService, audit: AuditPort) -> None:
        self._signer = signer
        self._end_users = end_users
        self._audit = audit

    async def issue(
        self,
        project: Project,
        tool_key: str,
        arguments: dict,
        *,
        end_user_external_id: Optional[str],
        member_id: Optional[str],
        ttl_seconds: int,
        actor_id: str,
    ) -> str:
        if end_user_external_id:
            subject = await self._end_users.resolve_subject(project.id, end_user_external_id, actor_id)
        elif member_id:
            subject = Subject(SubjectType.MEMBER, id=member_id)
        else:
            subject = Subject(SubjectType.PROJECT)
        token = self._signer.sign(
            APPROVAL_PURPOSE,
            {"prj": str(project.id), "tool": tool_key, "sub": subject.key, "args": arguments_hash(arguments)},
            ttl_seconds,
        )
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.TOOL_APPROVED.value,
            {"tool_key": tool_key, "kind": "call_approval", "subject": subject.key},
        )
        return token
