"""
Shared dependencies for Module 07 endpoints (SRS-07 FR-32 role and scope matrix).

``caller_dep`` builds a dependency that authenticates either a human (Clerk) or a machine (API key)
and enforces, per endpoint: a minimum project role for humans, the required scopes for machines,
and whether machines are allowed at all. Endpoints never touch the database.
"""
from dataclasses import dataclass
from typing import Annotated, Callable, List, Optional

from fastapi import Depends, Request

from app.api.deps import get_authenticated_context
from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.project import Project, ProjectRole
from app.schemas.auth import AuthenticatedActor
from app.services.tools.principal import role_at_least
from app.services.tools.providers import ToolsContainer, get_tools_container

ToolsDep = Annotated[ToolsContainer, Depends(get_tools_container)]


@dataclass
class ToolCaller:
    actor: AuthenticatedActor
    project: Project
    role: Optional[ProjectRole]
    request_id: Optional[str] = None

    @property
    def is_human(self) -> bool:
        return self.actor.actor_type == "user"

    @property
    def actor_id(self) -> str:
        return self.actor.identity_id


def caller_dep(
    scopes: List[str],
    *,
    human_min_role: ProjectRole,
    allow_machine: bool = True,
) -> Callable:
    """Build an endpoint dependency enforcing the role/scope requirements."""
    auth = get_authenticated_context(scopes)

    async def dependency(request: Request, actor: AuthenticatedActor = Depends(auth)) -> ToolCaller:
        project = getattr(request.state, "project", None)
        if project is None:
            raise NotFoundError("Project not found")
        role = getattr(request.state, "project_role", None)

        if actor.actor_type == "credential":
            if not allow_machine:
                raise ForbiddenError("This operation requires a signed-in project member")
        elif not role_at_least(role, human_min_role):
            raise ForbiddenError("Insufficient project permissions")

        return ToolCaller(
            actor=actor,
            project=project,
            role=role,
            request_id=getattr(request.state, "request_id", None),
        )

    dependency.__name__ = f"tool_caller_{human_min_role.value}_{'_'.join(s.replace(':', '_') for s in scopes) or 'human'}"
    return dependency


# Named dependencies (also the override points for tests)
read_caller = caller_dep(["tools:read"], human_min_role=ProjectRole.VIEWER)
admin_caller = caller_dep([], human_min_role=ProjectRole.ADMIN, allow_machine=False)
audit_caller = caller_dep(["tools:read"], human_min_role=ProjectRole.ADMIN)
toolset_caller = caller_dep(["tools:read"], human_min_role=ProjectRole.VIEWER)
invoke_caller = caller_dep(["tools:invoke"], human_min_role=ProjectRole.MEMBER)
end_user_assert_caller = caller_dep(["end_users:assert"], human_min_role=ProjectRole.ADMIN)
end_user_manage_caller = caller_dep(["end_users:manage"], human_min_role=ProjectRole.ADMIN)

ReadCaller = Annotated[ToolCaller, Depends(read_caller)]
AdminCaller = Annotated[ToolCaller, Depends(admin_caller)]
AuditCaller = Annotated[ToolCaller, Depends(audit_caller)]
ToolsetCaller = Annotated[ToolCaller, Depends(toolset_caller)]
InvokeCaller = Annotated[ToolCaller, Depends(invoke_caller)]
EndUserAssertCaller = Annotated[ToolCaller, Depends(end_user_assert_caller)]
EndUserManageCaller = Annotated[ToolCaller, Depends(end_user_manage_caller)]
