from typing import Annotated, Optional
from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    ProjectPurgedError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from app.core.logging import logger
from app.core.security import verify_clerk_token
from app.db.client import get_global_client, get_global_database
from app.models.project import Project, ProjectMember, ProjectRole, ProjectStatus
from app.models.user import UserRole
from app.repositories.project_member_repository import (
    ProjectMemberRepository,
    get_project_member_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import FilterParams, PaginationParams
from app.services.project_audit_service import (
    ProjectAuditService,
    get_project_audit_service,
)
from app.services.project_member_service import (
    ProjectMemberService,
    get_project_member_service,
)
from app.services.project_service import (
    ProjectService,
    get_project_service,
)
from app.services.user_service import UserService, get_user_service

# Native FastAPI security scheme
security = HTTPBearer(
    auto_error=False,
    description="Clerk Bearer JWT session token",
)


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> AuthenticatedUser:
    """
    FastAPI native security dependency enforcing Bearer authentication.
    Verifies Clerk token and synchronizes user identity into MongoDB.
    """
    if not credentials or not credentials.credentials:
        raise UnauthorizedError("Missing Authorization header")

    clerk_user = await verify_clerk_token(credentials.credentials)

    try:
        db_user = await user_service.sync_clerk_user(
            clerk_id=clerk_user.clerk_id,
            email=clerk_user.email,
            first_name=clerk_user.first_name,
            last_name=clerk_user.last_name,
            image_url=clerk_user.image_url,
        )
        if db_user is not None:
            return AuthenticatedUser(
                id=str(db_user.id),
                clerk_id=db_user.clerk_id,
                email=db_user.email,
                first_name=db_user.first_name,
                last_name=db_user.last_name,
                image_url=db_user.image_url,
                role=db_user.role,
                roles=[db_user.role.value],
                is_active=db_user.is_active,
                is_authenticated=True,
                created_at=db_user.created_at,
                updated_at=db_user.updated_at,
            )
    except Exception as exc:
        logger.debug(f"User DB sync bypassed (DB offline or uninitialized): {exc}")

    return clerk_user


async def get_optional_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
) -> Optional[AuthenticatedUser]:
    """
    FastAPI security dependency for endpoints that allow both guest and authenticated user access.
    """
    if not credentials or not credentials.credentials:
        return None

    try:
        return await verify_clerk_token(credentials.credentials)
    except Exception:
        return None


def get_pagination_params(
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 10,
    limit: Annotated[Optional[int], Query(ge=1, le=100, description="Limit override")] = None,
    offset: Annotated[Optional[int], Query(ge=0, description="Offset override")] = None,
) -> PaginationParams:
    """
    Dependency to parse pagination parameters with native FastAPI Query validation.
    """
    return PaginationParams(
        page=page,
        page_size=page_size,
        limit=limit,
        offset=offset,
    )


def get_filter_params(
    search: Annotated[Optional[str], Query(description="Text search filter")] = None,
    sort_by: Annotated[Optional[str], Query(description="Field name to sort results by")] = None,
    sort_order: Annotated[str, Query(pattern="^(asc|desc)$", description="Sort direction ('asc' or 'desc')")] = "asc",
) -> FilterParams:
    """
    Dependency to parse filtering, searching, and sorting parameters.
    """
    return FilterParams(
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,  # type: ignore
    )


def get_mongo_client(request: Request) -> AsyncIOMotorClient:
    """
    Dependency to retrieve the active MongoDB AsyncIOMotorClient.
    """
    client = getattr(request.app.state, "mongo_client", None) or get_global_client()
    if client is None:
        raise ServiceUnavailableError("MongoDB client is not initialized or unavailable")
    return client


def get_database(request: Request) -> AsyncIOMotorDatabase:
    """
    Dependency to retrieve the active MongoDB AsyncIOMotorDatabase.
    """
    db = getattr(request.app.state, "mongo_db", None) or get_global_database()
    if db is None:
        raise ServiceUnavailableError("MongoDB database is not initialized or unavailable")
    return db


def require_role(required_role: UserRole):
    """
    Factory dependency enforcing role-based access control (RBAC).
    """

    async def role_checker(
        current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    ) -> AuthenticatedUser:
        if current_user.role != required_role:
            raise ForbiddenError(
                f"Insufficient permissions: requires '{required_role.value}' role"
            )
        return current_user

    return role_checker


def require_project_role(*allowed_roles: ProjectRole):
    """
    FastAPI dependency factory enforcing project-level Role-Based Access Control (RBAC).
    Extracts project_id or slug from path/query parameter.
    Verifies caller's membership via ProjectMemberRepository / ProjectRepository.
    If caller is not a member (and not super admin), raises NotFoundError("Project not found")
    to eliminate tenant resource enumeration vulnerabilities per SRS Section 8.3.
    If caller is a member but lacks sufficient role, raises ForbiddenError.
    Attaches current project, caller role, and member to request.state and returns ProjectMember.
    """
    ROLE_HIERARCHY = {
        ProjectRole.VIEWER: 1,
        ProjectRole.MEMBER: 2,
        ProjectRole.ADMIN: 3,
        ProjectRole.OWNER: 4,
    }

    async def project_role_checker(
        request: Request,
        current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
        project_repo: Annotated[ProjectRepository, Depends(get_project_repository)],
        member_repo: Annotated[ProjectMemberRepository, Depends(get_project_member_repository)],
    ) -> ProjectMember:
        identifier = (
            request.path_params.get("project_id")
            or request.query_params.get("project_id")
            or request.path_params.get("slug")
            or request.query_params.get("slug")
        )
        if not identifier:
            raise NotFoundError("Project not found")

        project = await project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        is_super_admin = (current_user.role == UserRole.ADMIN)

        member = await member_repo.get_membership(project.id, current_user.clerk_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        # In SOFT_DELETED state: project access restricted to OWNER only (unless super admin)
        if project.status == ProjectStatus.SOFT_DELETED and not is_super_admin:
            if member is None or member.role != ProjectRole.OWNER:
                raise NotFoundError("Project not found")

        caller_role = (
            member.role
            if member is not None
            else (
                ProjectRole.OWNER
                if (is_super_admin and project.owner_id == current_user.clerk_id)
                else (ProjectRole.ADMIN if is_super_admin else None)
            )
        )

        if allowed_roles and not is_super_admin:
            if caller_role is None:
                raise ForbiddenError("Insufficient project permissions")
            min_required = min(ROLE_HIERARCHY.get(r, 0) for r in allowed_roles)
            caller_level = ROLE_HIERARCHY.get(caller_role, 0)
            if caller_role not in allowed_roles and caller_level < min_required:
                raise ForbiddenError("Insufficient project permissions")

        effective_member = member or ProjectMember(
            project_id=project.id,
            user_id=current_user.clerk_id,
            role=caller_role or ProjectRole.ADMIN,
        )

        request.state.project = project
        request.state.project_role = caller_role
        request.state.project_member = effective_member

        return effective_member

    return project_role_checker


# Modern Annotated Type Aliases for clean endpoint signatures
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]
OptionalUser = Annotated[Optional[AuthenticatedUser], Depends(get_optional_user)]
CurrentAdmin = Annotated[AuthenticatedUser, Depends(require_role(UserRole.ADMIN))]
PaginationDep = Annotated[PaginationParams, Depends(get_pagination_params)]
FilterDep = Annotated[FilterParams, Depends(get_filter_params)]
MongoClientDep = Annotated[AsyncIOMotorClient, Depends(get_mongo_client)]
DatabaseDep = Annotated[AsyncIOMotorDatabase, Depends(get_database)]
ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]
ProjectMemberServiceDep = Annotated[ProjectMemberService, Depends(get_project_member_service)]
ProjectAuditServiceDep = Annotated[ProjectAuditService, Depends(get_project_audit_service)]
