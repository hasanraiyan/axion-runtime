"""
Project Service implementing core domain business rules, lifecycle FSM, OCC, and multi-tenant isolation.
"""
from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends
from pymongo import AsyncMongoClient

from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.core.logging import logger
from app.db.client import get_global_client
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectMember,
    ProjectRole,
    ProjectSettings,
    ProjectStatus,
)
from app.repositories.credential_repository import (
    ProjectCredentialRepository,
    get_credential_repository,
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
from app.repositories.secret_repository import (
    ProjectSecretRepository,
    get_secret_repository,
)
from app.schemas.project import (
    ProjectCreateRequest,
    ProjectResponse,
    ProjectSummaryResponse,
    ProjectUpdateRequest,
    TransferOwnershipRequest,
)


class ProjectService:
    """
    Domain service orchestrating Project lifecycle, membership, optimistic locking,
    FSM state transitions, and audit logging. Decoupled from HTTP transports.
    """

    def __init__(
        self,
        project_repo: Optional[ProjectRepository] = None,
        member_repo: Optional[ProjectMemberRepository] = None,
        audit_repo: Optional[ProjectAuditRepository] = None,
        secret_repo: Optional[ProjectSecretRepository] = None,
        credential_repo: Optional[ProjectCredentialRepository] = None,
        mongo_client: Optional[AsyncMongoClient] = None,
    ) -> None:
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.member_repo = member_repo if member_repo is not None else get_project_member_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.secret_repo = secret_repo
        self.credential_repo = credential_repo
        self.mongo_client = mongo_client

    def _get_client(self) -> Optional[AsyncMongoClient]:
        """Obtain MongoDB client for transaction session management."""
        return self.mongo_client or get_global_client()

    def _to_response(
        self,
        project: Project,
        user_role: Optional[ProjectRole] = None,
        member_count: int = 1,
    ) -> ProjectResponse:
        """Helper to transform Project document into ProjectResponse DTO."""
        return ProjectResponse(
            id=str(project.id),
            name=project.name,
            slug=project.slug,
            description=project.description,
            owner_id=project.owner_id,
            status=project.status,
            tags=project.tags,
            settings=project.settings,
            metadata=project.metadata,
            version=project.version,
            user_role=user_role,
            member_count=member_count,
            created_at=project.created_at,
            updated_at=project.updated_at,
            archived_at=project.archived_at,
            deleted_at=project.deleted_at,
            purge_after=project.purge_after,
        )

    def _generate_base_slug(self, name: str) -> str:
        """Convert a project name into a lowercase, URL-safe base slug."""
        normalized = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
        normalized = re.sub(r"-+", "-", normalized)
        return normalized if len(normalized) >= 2 else "project"

    async def _resolve_unique_slug(self, base_slug: str) -> str:
        """
        Check if base_slug collides with any project that still owns it. If it does,
        attempt up to 3 times to append a 4-hex random suffix.

        Slugs are reserved for every non-purged project (ACTIVE, ARCHIVED and
        SOFT_DELETED). Reusing a soft-deleted/archived project's slug would make
        a later restore/unarchive violate the unique active-slug index and fail
        with a database error.
        """
        existing = await self.project_repo.get_by_slug(base_slug)
        if existing is None or existing.status == ProjectStatus.PURGED:
            return base_slug

        for _ in range(3):
            suffix = secrets.token_hex(2)  # 4 hexadecimal characters
            candidate = f"{base_slug}-{suffix}"
            candidate_existing = await self.project_repo.get_by_slug(candidate)
            if candidate_existing is None or candidate_existing.status == ProjectStatus.PURGED:
                return candidate

        raise ConflictError("Unable to auto-generate a unique project slug after 3 attempts")

    async def create_project(
        self,
        user_id: str,
        data: ProjectCreateRequest,
    ) -> ProjectResponse:
        """
        Create a new Project (FR-01):
        - Generates/validates unique slug.
        - Sets version=1, status=ACTIVE.
        - Registers caller as OWNER in project and creates ProjectMember.
        - Emits PROJECT_CREATED audit log.
        """
        if data.slug:
            # Explicit slug requested. Reserve it until the owning project is purged.
            existing = await self.project_repo.get_by_slug(data.slug)
            if existing is not None and existing.status != ProjectStatus.PURGED:
                raise ConflictError("Project slug already in use")
            chosen_slug = data.slug
        else:
            base_slug = self._generate_base_slug(data.name)
            chosen_slug = await self._resolve_unique_slug(base_slug)

        project = Project(
            name=data.name,
            slug=chosen_slug,
            description=data.description,
            owner_id=user_id,
            status=ProjectStatus.ACTIVE,
            tags=data.tags or [],
            settings=data.settings or ProjectSettings(),
            metadata=data.metadata or {},
            version=1,
        )

        created_project = await self.project_repo.create(project)

        # Register creator as OWNER member. If this fails, remove the project so
        # the slug is not left orphaned and blocked for future create attempts.
        member = ProjectMember(
            project_id=created_project.id,
            user_id=user_id,
            role=ProjectRole.OWNER,
            joined_at=datetime.now(timezone.utc),
        )
        try:
            await self.member_repo.create(member)
        except Exception:
            try:
                await self.project_repo.delete(created_project)
            except Exception as cleanup_exc:
                logger.error(
                    f"Failed to roll back orphaned project '{created_project.id}' "
                    f"('{created_project.slug}'): {cleanup_exc}"
                )
            raise

        # Log PROJECT_CREATED audit event
        await self.audit_repo.log_event(
            project_id=created_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_CREATED,
            payload={
                "name": created_project.name,
                "slug": created_project.slug,
                "owner_id": user_id,
            },
        )

        logger.info(f"Project '{created_project.id}' ('{created_project.slug}') created by user '{user_id}'.")
        return self._to_response(created_project, user_role=ProjectRole.OWNER, member_count=1)

    async def get_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
        include_deleted: bool = False,
    ) -> ProjectResponse:
        """
        Retrieve project by ID or slug (FR-02):
        - Enforces membership verification. Raises NotFoundError if caller is not a member
          (preventing tenant enumeration per SRS Section 8.3).
        - Rejects purged projects with ProjectPurgedError.
        - Returns member_count and caller's effective role.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            # Multi-tenant isolation rule: return 404 rather than 403 to prevent discovery
            raise NotFoundError("Project not found")

        # Soft-deleted projects are visible to OWNER only
        if project.status == ProjectStatus.SOFT_DELETED:
            if not is_super_admin:
                if member is None or member.role != ProjectRole.OWNER:
                    raise NotFoundError("Project not found")

        effective_role = member.role if member is not None else (
            ProjectRole.OWNER if (is_super_admin and project.owner_id == user_id) else (
                ProjectRole.ADMIN if is_super_admin else None
            )
        )
        member_count = await self.member_repo.count_members(project.id)

        return self._to_response(project, user_role=effective_role, member_count=member_count)

    async def update_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        data: ProjectUpdateRequest,
        is_super_admin: bool = False,
    ) -> ProjectResponse:
        """
        Partial update project metadata and settings (FR-03, FR-09):
        - Restricts update capability to OWNER or ADMIN.
        - Enforces FSM mutation prohibition in ARCHIVED or SOFT_DELETED states.
        - Applies Optimistic Concurrency Control (OCC) using version field.
        - Updates updated_at, increments version, and emits PROJECT_UPDATED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
            raise ForbiddenError("Only OWNER or ADMIN can modify project configuration")

        if project.status == ProjectStatus.ARCHIVED:
            raise ProjectArchivedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        if project.version != data.version:
            raise ConflictError("Project version conflict: document was modified by a concurrent request")

        update_dict: Dict[str, Any] = {}
        if data.name is not None:
            update_dict["name"] = data.name
        if data.description is not None:
            update_dict["description"] = data.description
        if data.tags is not None:
            update_dict["tags"] = data.tags
        if data.settings is not None:
            update_dict["settings"] = data.settings.model_dump()
        if data.metadata is not None:
            update_dict["metadata"] = data.metadata

        updated_project = await self.project_repo.update_with_version(
            project_id=project.id,
            update_dict=update_dict,
            expected_version=data.version,
        )

        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_UPDATED,
            payload={
                "changes": update_dict,
                "version": updated_project.version,
            },
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        effective_role = member.role if member is not None else ProjectRole.ADMIN
        return self._to_response(updated_project, user_role=effective_role, member_count=member_count)

    async def list_projects(
        self,
        user_id: str,
        status: Optional[ProjectStatus] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 10,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
        include_archived: bool = False,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectSummaryResponse], int]:
        """
        List projects accessible to user (FR-04):
        - Queries project_members to retrieve projects where caller is a member.
        - Excludes ARCHIVED and DELETED by default unless explicitly requested.
        - Supports text search, tag filtering, sorting, and pagination.
        """
        project_ids = await self.member_repo.list_project_ids_for_user(user_id)
        if not project_ids:
            return ([], 0)

        # Default status filtering behavior per FR-04. Each flag only adds its
        # own state: `include_archived` must never expose soft-deleted projects
        # (and vice versa). PURGED projects are never listed.
        if status is not None:
            query_statuses = [status]
        else:
            query_statuses = [ProjectStatus.ACTIVE]
            if include_archived:
                query_statuses.append(ProjectStatus.ARCHIVED)
            if include_deleted:
                query_statuses.append(ProjectStatus.SOFT_DELETED)

        actual_skip = skip if skip is not None else max(0, (page - 1) * page_size)
        actual_limit = limit if limit is not None else page_size

        projects, total = await self.project_repo.list_by_ids(
            project_ids=project_ids,
            statuses=query_statuses,
            search=search,
            tags=tags,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=actual_skip,
            limit=actual_limit,
        )

        summaries: List[ProjectSummaryResponse] = []
        for proj in projects:
            member = await self.member_repo.get_membership(proj.id, user_id)
            user_role = member.role if member is not None else ProjectRole.MEMBER
            count = await self.member_repo.count_members(proj.id)

            summaries.append(
                ProjectSummaryResponse(
                    id=str(proj.id),
                    name=proj.name,
                    slug=proj.slug,
                    description=proj.description,
                    owner_id=proj.owner_id,
                    status=proj.status,
                    tags=proj.tags,
                    user_role=user_role,
                    member_count=count,
                    created_at=proj.created_at,
                    updated_at=proj.updated_at,
                )
            )

        return (summaries, total)

    async def transfer_ownership(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        data: TransferOwnershipRequest,
    ) -> ProjectResponse:
        """
        Transfer project ownership (FR-07):
        - Restricted strictly to current OWNER.
        - Target must be an active project member.
        - Executes within MongoDB multi-document transaction using client session.
        - Updates project owner_id, target member role to OWNER, former owner to specified role.
        - Emits OWNERSHIP_TRANSFERRED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))

        caller_member = await self.member_repo.get_membership(project.id, user_id)
        if caller_member is None or caller_member.role != ProjectRole.OWNER or project.owner_id != user_id:
            raise ForbiddenError("Only the project OWNER can transfer ownership")

        target_user_id = data.new_owner_user_id
        if target_user_id == user_id:
            raise BadRequestError("Target user is already the project owner")

        target_member = await self.member_repo.get_membership(project.id, target_user_id)
        if target_member is None:
            raise BadRequestError("Target user must be an active member of the project")

        if data.former_owner_role == ProjectRole.OWNER:
            raise BadRequestError("Former owner role cannot remain OWNER")

        client = self._get_client()
        if client is not None:
            try:
                async with await client.start_session() as session:
                    async with session.start_transaction():
                        return await self._execute_transfer(
                            project=project,
                            user_id=user_id,
                            caller_member=caller_member,
                            target_member=target_member,
                            data=data,
                            session=session,
                        )
            except Exception as exc:
                # Handle topologies without multi-document transaction support (e.g. standalone test mongod)
                if "transaction numbers are only allowed" in str(exc).lower() or "replica set" in str(exc).lower():
                    return await self._execute_transfer(
                        project=project,
                        user_id=user_id,
                        caller_member=caller_member,
                        target_member=target_member,
                        data=data,
                        session=None,
                    )
                raise
        else:
            return await self._execute_transfer(
                project=project,
                user_id=user_id,
                caller_member=caller_member,
                target_member=target_member,
                data=data,
                session=None,
            )

    async def _execute_transfer(
        self,
        project: Project,
        user_id: str,
        caller_member: ProjectMember,
        target_member: ProjectMember,
        data: TransferOwnershipRequest,
        session: Optional[Any] = None,
    ) -> ProjectResponse:
        """Internal helper executing ownership transfer writes across project, members, and audit collections."""
        # 1. Update project owner_id & version
        updated_project = await self.project_repo.update_with_version(
            project_id=project.id,
            update_dict={"owner_id": data.new_owner_user_id},
            expected_version=project.version,
            session=session,
        )

        # 2. Update target member role to OWNER
        target_member.role = ProjectRole.OWNER
        await self.member_repo.update(target_member, session=session)

        # 3. Update former owner role to caller-specified role
        caller_member.role = data.former_owner_role
        await self.member_repo.update(caller_member, session=session)

        # 4. Log OWNERSHIP_TRANSFERRED audit event
        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.OWNERSHIP_TRANSFERRED,
            target_user_id=data.new_owner_user_id,
            payload={
                "previous_owner_id": user_id,
                "new_owner_id": data.new_owner_user_id,
                "former_owner_role": data.former_owner_role.value,
            },
            session=session,
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        logger.info(f"Ownership of project '{project.id}' transferred from '{user_id}' to '{data.new_owner_user_id}'.")
        return self._to_response(updated_project, user_role=data.former_owner_role, member_count=member_count)

    async def archive_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
    ) -> ProjectResponse:
        """
        Transition ACTIVE -> ARCHIVED (FSM T-02):
        - Restricted to OWNER or ADMIN.
        - Sets archived_at=now, version+=1, and emits PROJECT_ARCHIVED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
            raise ForbiddenError("Only OWNER or ADMIN can archive project")

        if project.status == ProjectStatus.ARCHIVED:
            raise InvalidStateTransitionError(from_state="archived", to_state="archived")
        if project.status != ProjectStatus.ACTIVE:
            raise InvalidStateTransitionError(from_state=project.status.value, to_state="archived")

        now = datetime.now(timezone.utc)
        updated_project = await self.project_repo.transition_status(
            project_id=project.id,
            from_state=ProjectStatus.ACTIVE,
            to_state=ProjectStatus.ARCHIVED,
            expected_version=project.version,
            additional_updates={"archived_at": now},
        )

        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_ARCHIVED,
            payload={"archived_at": now.isoformat()},
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        effective_role = member.role if member is not None else ProjectRole.ADMIN
        return self._to_response(updated_project, user_role=effective_role, member_count=member_count)

    async def unarchive_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
    ) -> ProjectResponse:
        """
        Transition ARCHIVED -> ACTIVE (FSM T-03):
        - Restricted to OWNER or ADMIN.
        - Resets archived_at=None, version+=1, and emits PROJECT_UNARCHIVED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and member.role not in (ProjectRole.OWNER, ProjectRole.ADMIN):
            raise ForbiddenError("Only OWNER or ADMIN can unarchive project")

        if project.status != ProjectStatus.ARCHIVED:
            raise InvalidStateTransitionError(from_state=project.status.value, to_state="active")

        updated_project = await self.project_repo.transition_status(
            project_id=project.id,
            from_state=ProjectStatus.ARCHIVED,
            to_state=ProjectStatus.ACTIVE,
            expected_version=project.version,
            additional_updates={"archived_at": None},
        )

        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_UNARCHIVED,
            payload={"unarchived_at": datetime.now(timezone.utc).isoformat()},
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        effective_role = member.role if member is not None else ProjectRole.ADMIN
        return self._to_response(updated_project, user_role=effective_role, member_count=member_count)

    async def soft_delete_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
    ) -> ProjectResponse:
        """
        Transition ACTIVE/ARCHIVED -> SOFT_DELETED (FSM T-04, T-05):
        - Restricted strictly to OWNER.
        - Sets deleted_at=now, purge_after=now + retention_days, version+=1.
        - Emits PROJECT_DELETED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and (member is None or member.role != ProjectRole.OWNER or project.owner_id != user_id):
            raise ForbiddenError("Only the project OWNER can delete the project")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise InvalidStateTransitionError(from_state="soft_deleted", to_state="soft_deleted")

        now = datetime.now(timezone.utc)
        retention_days = project.settings.retention_days if project.settings else 30
        purge_after = now + timedelta(days=retention_days)

        updated_project = await self.project_repo.transition_status(
            project_id=project.id,
            from_state=project.status,
            to_state=ProjectStatus.SOFT_DELETED,
            expected_version=project.version,
            additional_updates={
                "deleted_at": now,
                "purge_after": purge_after,
            },
        )

        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_DELETED,
            payload={
                "deleted_at": now.isoformat(),
                "purge_after": purge_after.isoformat(),
                "retention_days": retention_days,
            },
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        effective_role = member.role if member is not None else ProjectRole.OWNER
        return self._to_response(updated_project, user_role=effective_role, member_count=member_count)

    async def restore_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
    ) -> ProjectResponse:
        """
        Transition SOFT_DELETED -> ACTIVE (FSM T-06):
        - Restricted strictly to OWNER.
        - Guard: now <= purge_after. If expired, raises ProjectPurgedError.
        - Resets deleted_at=None, purge_after=None, version+=1.
        - Emits PROJECT_RESTORED audit log.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and (member is None or member.role != ProjectRole.OWNER or project.owner_id != user_id):
            raise ForbiddenError("Only the project OWNER can restore the project")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status != ProjectStatus.SOFT_DELETED:
            raise InvalidStateTransitionError(from_state=project.status.value, to_state="active")

        now = datetime.now(timezone.utc)
        if project.purge_after is not None and now > project.purge_after:
            raise ProjectPurgedError(str(project.id))

        updated_project = await self.project_repo.transition_status(
            project_id=project.id,
            from_state=ProjectStatus.SOFT_DELETED,
            to_state=ProjectStatus.ACTIVE,
            expected_version=project.version,
            additional_updates={
                "deleted_at": None,
                "purge_after": None,
            },
        )

        await self.audit_repo.log_event(
            project_id=updated_project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_RESTORED,
            payload={"restored_at": now.isoformat()},
        )

        member_count = await self.member_repo.count_members(updated_project.id)
        effective_role = member.role if member is not None else ProjectRole.OWNER
        return self._to_response(updated_project, user_role=effective_role, member_count=member_count)

    async def purge_project(
        self,
        identifier: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        is_super_admin: bool = False,
    ) -> Dict[str, Any]:
        """
        Terminal transition SOFT_DELETED -> PURGED (FSM T-07):
        - Restricted to OWNER or background sweeper.
        - Direct transition from ACTIVE or ARCHIVED is strictly rejected with InvalidStateTransitionError.
        - Cascades cleanup across project_members and records PROJECT_PURGED event.
        """
        project = await self.project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        member = await self.member_repo.get_membership(project.id, user_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        if not is_super_admin and (member is None or member.role != ProjectRole.OWNER or project.owner_id != user_id):
            raise ForbiddenError("Only the project OWNER can purge the project")

        if project.status != ProjectStatus.SOFT_DELETED:
            raise InvalidStateTransitionError(from_state=project.status.value, to_state="purged")

        now = datetime.now(timezone.utc)
        # 1. Update project status to PURGED
        await self.project_repo.transition_status(
            project_id=project.id,
            from_state=ProjectStatus.SOFT_DELETED,
            to_state=ProjectStatus.PURGED,
            expected_version=project.version,
            additional_updates={"deleted_at": now},
        )

        # 2. Cascade delete project_members, child secrets, and credentials
        deleted_members = await self.member_repo.delete_by_project_id(project.id)
        if self.secret_repo is not None:
            await self.secret_repo.purge_by_project(project.id)
        if self.credential_repo is not None:
            deleted_credentials = await self.credential_repo.purge_by_project(project.id)
            if deleted_credentials > 0:
                await self.audit_repo.log_event(
                    project_id=project.id,
                    actor_id=user_id,
                    action=ProjectAuditAction.CREDENTIAL_PURGED,
                    payload={
                        "purged_at": now.isoformat(),
                        "deleted_credentials_count": deleted_credentials,
                    },
                )

        # 3. Emit PROJECT_PURGED audit log
        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=user_id,
            action=ProjectAuditAction.PROJECT_PURGED,
            payload={
                "purged_at": now.isoformat(),
                "deleted_members_count": deleted_members,
            },
        )

        logger.info(f"Project '{project.id}' permanently purged by '{user_id}'.")
        return {
            "message": f"Project '{project.id}' successfully purged",
            "purged": True,
            "deleted_members_count": deleted_members,
        }


def get_project_service(
    project_repo: ProjectRepository = Depends(get_project_repository),
    member_repo: ProjectMemberRepository = Depends(get_project_member_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    secret_repo: ProjectSecretRepository = Depends(get_secret_repository),
    credential_repo: ProjectCredentialRepository = Depends(get_credential_repository),
) -> ProjectService:
    """Dependency injection provider for ProjectService."""
    return ProjectService(
        project_repo=project_repo,
        member_repo=member_repo,
        audit_repo=audit_repo,
        secret_repo=secret_repo,
        credential_repo=credential_repo,
    )
