"""
Project Member Service implementing membership management, invitations, role modifications, and RBAC hierarchy rules.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.core.logging import logger
from app.models.project import (
    ProjectAuditAction,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
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
from app.repositories.user_repository import (
    UserRepository,
    get_user_repository,
)
from app.schemas.project import (
    AddMemberRequest,
    MemberResponse,
    UpdateMemberRoleRequest,
)


class ProjectMemberService:
    """
    Domain service handling project member roster operations, invitations,
    role assignments, and membership revocation. Decoupled from HTTP transports.
    """

    def __init__(
        self,
        member_repo: Optional[ProjectMemberRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
        audit_repo: Optional[ProjectAuditRepository] = None,
        user_repo: Optional[UserRepository] = None,
    ) -> None:
        self.member_repo = member_repo if member_repo is not None else get_project_member_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.user_repo = user_repo if user_repo is not None else get_user_repository()

    async def _to_member_response(self, member: ProjectMember) -> MemberResponse:
        """Helper converting ProjectMember entity to enriched MemberResponse DTO."""
        email: Optional[str] = None
        first_name: Optional[str] = None
        last_name: Optional[str] = None

        if self.user_repo is not None:
            try:
                user = await self.user_repo.get_by_clerk_id(member.user_id)
                if user is not None:
                    email_val = getattr(user, "email", None)
                    fn_val = getattr(user, "first_name", None)
                    ln_val = getattr(user, "last_name", None)
                    email = str(email_val) if isinstance(email_val, str) else None
                    first_name = str(fn_val) if isinstance(fn_val, str) else None
                    last_name = str(ln_val) if isinstance(ln_val, str) else None
            except Exception as exc:
                logger.debug(f"User profile lookup omitted for member '{member.user_id}': {exc}")

        return MemberResponse(
            id=str(member.id),
            project_id=str(member.project_id),
            user_id=member.user_id,
            role=member.role,
            invited_by=member.invited_by,
            joined_at=member.joined_at,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

    async def add_member(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        data: AddMemberRequest,
        is_super_admin: bool = False,
    ) -> MemberResponse:
        """
        Add a member to a project (FR-05):
        - Requires caller to have OWNER or ADMIN role.
        - Direct assignment of OWNER role is prohibited.
        - Enforces active project FSM state (rejects ARCHIVED, SOFT_DELETED, PURGED).
        - Prevents duplicate membership (translates MongoDB unique constraint into ConflictError).
        - Emits MEMBER_ADDED audit event.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.ARCHIVED:
            raise ProjectArchivedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        if not is_super_admin:
            actor_member = await self.member_repo.get_membership(project.id, actor_id)
            if actor_member is None:
                raise NotFoundError("Project not found")
            if actor_member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
                raise ForbiddenError("Only OWNER or ADMIN can add members to the project")

        if data.role == ProjectRole.OWNER:
            raise BadRequestError("Direct assignment of OWNER is prohibited. Use ownership transfer.")

        # Check existing membership
        existing = await self.member_repo.get_membership(project.id, data.user_id)
        if existing is not None:
            raise ConflictError("User is already a member of this project")

        member = ProjectMember(
            project_id=project.id,
            user_id=data.user_id,
            role=data.role,
            invited_by=actor_id,
            joined_at=datetime.now(timezone.utc),
        )

        created_member = await self.member_repo.create(member)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MEMBER_ADDED,
            target_user_id=data.user_id,
            payload={
                "role": data.role.value,
                "invited_by": actor_id,
            },
        )

        logger.info(f"User '{data.user_id}' added as '{data.role.value}' to project '{project.id}' by '{actor_id}'.")
        return await self._to_member_response(created_member)

    async def update_member_role(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        target_user_id: str,
        data: UpdateMemberRoleRequest,
        is_super_admin: bool = False,
    ) -> MemberResponse:
        """
        Modify assigned role for an existing project member (FR-06):
        - Requires caller to have OWNER or ADMIN role.
        - Direct promotion to OWNER is prohibited (must use transfer_ownership).
        - The OWNER role cannot be modified.
        - ADMIN hierarchy boundary: an ADMIN cannot modify another ADMIN or the OWNER.
        - Emits MEMBER_ROLE_UPDATED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.ARCHIVED:
            raise ProjectArchivedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        if not is_super_admin:
            actor_member = await self.member_repo.get_membership(project.id, actor_id)
            if actor_member is None:
                raise NotFoundError("Project not found")
            if actor_member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
                raise ForbiddenError("Only OWNER or ADMIN can modify member roles")
        else:
            actor_member = None

        target_member = await self.member_repo.get_membership(project.id, target_user_id)
        if target_member is None:
            raise NotFoundError(f"Member '{target_user_id}' not found in project")

        if data.role == ProjectRole.OWNER:
            raise BadRequestError("Direct upgrade to OWNER is prohibited. Use ownership transfer.")

        if target_member.role == ProjectRole.OWNER or project.owner_id == target_user_id:
            raise ForbiddenError("Cannot modify the role of the project OWNER")

        # ADMIN hierarchy boundary enforcement
        if not is_super_admin and actor_member is not None and actor_member.role == ProjectRole.ADMIN:
            if target_member.role in (ProjectRole.ADMIN, ProjectRole.OWNER):
                raise ForbiddenError("ADMIN cannot modify roles of other ADMINs or the OWNER")

        old_role = target_member.role
        target_member.role = data.role
        updated_member = await self.member_repo.update(target_member)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MEMBER_ROLE_UPDATED,
            target_user_id=target_user_id,
            payload={
                "previous_role": old_role.value,
                "new_role": data.role.value,
            },
        )

        logger.info(
            f"Role for user '{target_user_id}' in project '{project.id}' updated "
            f"from '{old_role.value}' to '{data.role.value}' by '{actor_id}'."
        )
        return await self._to_member_response(updated_member)

    async def remove_member(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        target_user_id: str,
        is_super_admin: bool = False,
    ) -> Dict[str, Any]:
        """
        Revoke project membership or process member self-leave (FR-06):
        - Allowed for OWNER, ADMIN, or self-leave.
        - Sole OWNER invariant: The OWNER cannot leave or be removed without completing ownership transfer.
        - ADMIN hierarchy boundary: ADMIN cannot remove another ADMIN or the OWNER.
        - Emits MEMBER_REMOVED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        target_member = await self.member_repo.get_membership(project.id, target_user_id)
        if target_member is None:
            raise NotFoundError(f"Member '{target_user_id}' not found in project")

        # Sole OWNER Invariant (FR-06 / Scenario 6)
        if target_member.role == ProjectRole.OWNER or project.owner_id == target_user_id:
            raise ForbiddenError("The project OWNER cannot leave or be removed without transferring ownership first")

        is_self_leave = (actor_id == target_user_id)

        # In ARCHIVED state: mutations are prohibited, but self-leave is allowed per Section 4.7
        if project.status == ProjectStatus.ARCHIVED and not is_self_leave:
            raise ProjectArchivedError(str(project.id))

        if not is_self_leave and not is_super_admin:
            actor_member = await self.member_repo.get_membership(project.id, actor_id)
            if actor_member is None:
                raise NotFoundError("Project not found")
            if actor_member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
                raise ForbiddenError("Only OWNER or ADMIN can remove project members")

            # ADMIN hierarchy boundary enforcement
            if actor_member.role == ProjectRole.ADMIN:
                if target_member.role in (ProjectRole.ADMIN, ProjectRole.OWNER):
                    raise ForbiddenError("ADMIN cannot remove another ADMIN or the OWNER")

        await self.member_repo.delete(target_member)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MEMBER_REMOVED,
            target_user_id=target_user_id,
            payload={
                "removed_role": target_member.role.value,
                "is_self_leave": is_self_leave,
            },
        )

        logger.info(
            f"Member '{target_user_id}' removed from project '{project.id}' by '{actor_id}' "
            f"(self_leave={is_self_leave})."
        )
        return {
            "message": f"Member '{target_user_id}' successfully removed from project",
            "removed": True,
            "user_id": target_user_id,
        }

    async def list_members(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        skip: int = 0,
        limit: int = 50,
        is_super_admin: bool = False,
    ) -> Tuple[List[MemberResponse], int]:
        """
        List members registered to a project with pagination:
        - Verifies caller membership (prevents unauthorized discovery).
        - Returns list of enriched MemberResponse DTOs and total count.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError("Project not found")

        if not is_super_admin:
            caller_member = await self.member_repo.get_membership(project.id, user_id)
            if caller_member is None:
                raise NotFoundError("Project not found")

        items, total = await self.member_repo.list_members(project.id, skip=skip, limit=limit)
        member_responses = [await self._to_member_response(m) for m in items]
        return (member_responses, total)


def get_project_member_service(
    member_repo: ProjectMemberRepository = Depends(get_project_member_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    user_repo: UserRepository = Depends(get_user_repository),
) -> ProjectMemberService:
    """Dependency injection provider for ProjectMemberService."""
    return ProjectMemberService(
        member_repo=member_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        user_repo=user_repo,
    )
