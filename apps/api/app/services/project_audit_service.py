"""
Project Audit Service providing audit log retrieval and security event queries.
"""
from typing import List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.project import ProjectAuditLog, ProjectRole
from app.repositories.project_audit_repository import (
    ProjectAuditRepository,
    get_project_audit_repository,
)
from app.repositories.project_member_repository import (
    ProjectMemberRepository,
    get_project_member_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.schemas.project import AuditLogResponse


class ProjectAuditService:
    """
    Domain service for querying immutable project audit logs (FR-10).
    Decoupled from HTTP transports.
    """

    def __init__(
        self,
        audit_repo: Optional[ProjectAuditRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
        member_repo: Optional[ProjectMemberRepository] = None,
    ) -> None:
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.member_repo = member_repo if member_repo is not None else get_project_member_repository()

    def _to_audit_response(self, log: ProjectAuditLog) -> AuditLogResponse:
        """Helper transforming ProjectAuditLog document to AuditLogResponse DTO."""
        return AuditLogResponse(
            id=str(log.id),
            project_id=str(log.project_id),
            actor_id=log.actor_id,
            action=log.action.value if hasattr(log.action, "value") else str(log.action),
            target_user_id=log.target_user_id,
            payload=log.payload or {},
            created_at=log.created_at,
        )

    async def list_audit_logs(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        skip: int = 0,
        limit: int = 50,
        is_super_admin: bool = False,
    ) -> Tuple[List[AuditLogResponse], int]:
        """
        List audit logs for a project (FR-10):
        - Restricted to OWNER and ADMIN roles.
        - Non-members receive NotFoundError (preventing discovery per SRS Section 8.3).
        - Members lacking sufficient role receive ForbiddenError.
        - Returns ordered list (newest first) and total count.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError("Project not found")

        if not is_super_admin:
            member = await self.member_repo.get_membership(project.id, user_id)
            if member is None:
                raise NotFoundError("Project not found")
            if member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
                raise ForbiddenError("Only OWNER or ADMIN can view project audit logs")

        items, total = await self.audit_repo.list_events(project.id, skip=skip, limit=limit)
        responses = [self._to_audit_response(item) for item in items]
        return (responses, total)


def get_project_audit_service(
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    member_repo: ProjectMemberRepository = Depends(get_project_member_repository),
) -> ProjectAuditService:
    """Dependency injection provider for ProjectAuditService."""
    return ProjectAuditService(
        audit_repo=audit_repo,
        project_repo=project_repo,
        member_repo=member_repo,
    )
