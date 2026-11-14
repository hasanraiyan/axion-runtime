"""
Project Management API Endpoints (MOD-01) implementing SRS-01 Section 7.2.
Provides project workspace lifecycle, RBAC membership governance, OCC, and audit log queries.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import (
    CurrentUser,
    ProjectAuditServiceDep,
    ProjectMemberServiceDep,
    ProjectServiceDep,
    require_project_role,
)
from app.models.project import ProjectRole, ProjectStatus
from app.models.user import UserRole
from app.schemas.common import (
    ApiErrorResponse,
    ApiResponse,
    PaginatedData,
    PaginatedResponse,
    PaginationParams,
)
from app.schemas.project import (
    AddMemberRequest,
    AuditLogResponse,
    MemberResponse,
    ProjectCreateRequest,
    ProjectResponse,
    ProjectSummaryResponse,
    ProjectUpdateRequest,
    TransferOwnershipRequest,
    UpdateMemberRoleRequest,
)
from app.utils.pagination import build_pagination_meta, resolve_pagination

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Project Creation & Listing (Root Routes)
# ------------------------------------------------------------------------------


@router.post(
    "",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create Project",
    description="Create a new project workspace. Automatically assigns caller as OWNER and emits PROJECT_CREATED audit log.",
    operation_id="create_project",
    responses={
        status.HTTP_201_CREATED: {"description": "Project created successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Missing or invalid authentication token"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Explicit slug conflict or unresolvable collision"},
    },
)
@router.post(
    "/",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def create_project(
    body: ProjectCreateRequest,
    current_user: CurrentUser,
    project_service: ProjectServiceDep,
) -> ApiResponse[ProjectResponse]:
    project = await project_service.create_project(
        user_id=current_user.clerk_id,
        data=body,
    )
    return ApiResponse(
        data=project,
        message=f"Project '{project.name}' created successfully",
    )


@router.get(
    "",
    response_model=PaginatedResponse[ProjectSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="List Caller Projects",
    description="List projects accessible to caller with pagination, text search, status, and tag filtering.",
    operation_id="list_caller_projects",
    responses={
        status.HTTP_200_OK: {"description": "Projects retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Missing or invalid authentication token"},
    },
)
@router.get(
    "/",
    response_model=PaginatedResponse[ProjectSummaryResponse],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def list_projects(
    current_user: CurrentUser,
    project_service: ProjectServiceDep,
    status: Optional[ProjectStatus] = Query(None, description="Filter by project lifecycle status"),
    search: Optional[str] = Query(None, description="Search by name, description, or slug"),
    tags: Optional[List[str]] = Query(None, description="Filter by tags"),
    sort_by: str = Query("updated_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order direction"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
    include_archived: bool = Query(False, description="Include archived projects"),
    include_deleted: bool = Query(False, description="Include soft-deleted projects"),
) -> PaginatedResponse[ProjectSummaryResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await project_service.list_projects(
        user_id=current_user.clerk_id,
        status=status,
        search=search,
        tags=tags,
        sort_by=sort_by,
        sort_order=sort_order,
        page=effective_page,
        page_size=effective_page_size,
        skip=skip,
        limit=effective_page_size,
        include_archived=include_archived,
        include_deleted=include_deleted,
    )

    meta = build_pagination_meta(total_records=total, page=effective_page, page_size=effective_page_size)
    return PaginatedResponse(
        data=PaginatedData(items=items, pagination=meta),
        message="Projects retrieved successfully",
    )


# ------------------------------------------------------------------------------
# 2. Single Project Operations & Lifecycle Governance
# ------------------------------------------------------------------------------


@router.get(
    "/{project_id}",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Project by ID or Slug",
    description="Retrieve project metadata, settings, calculated member count, and caller's effective role. Enforces multi-tenant isolation.",
    operation_id="get_project_by_id_or_slug",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Project retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
async def get_project(
    project_id: str = Path(..., description="Project 24-char ObjectId hex or URL-safe slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.get_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=project,
        message="Project retrieved successfully",
    )


@router.patch(
    "/{project_id}",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Project with OCC",
    description="Partial update of project configuration and settings with Optimistic Concurrency Control (version checking).",
    operation_id="update_project",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project updated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "OCC version conflict or FSM state mutation prohibition"},
    },
)
async def update_project(
    body: ProjectUpdateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.update_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        data=body,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=project,
        message="Project updated successfully",
    )


@router.post(
    "/{project_id}/archive",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Archive Project",
    description="Transition project from ACTIVE to ARCHIVED frozen read-only state (FSM T-02).",
    operation_id="archive_project",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project archived successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Illegal state transition"},
    },
)
async def archive_project(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.archive_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=project,
        message="Project archived successfully",
    )


@router.post(
    "/{project_id}/unarchive",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Unarchive Project",
    description="Transition project from ARCHIVED to ACTIVE operational state (FSM T-03).",
    operation_id="unarchive_project",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project unarchived successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Illegal state transition"},
    },
)
async def unarchive_project(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.unarchive_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=project,
        message="Project unarchived successfully",
    )


@router.post(
    "/{project_id}/restore",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Restore Soft-Deleted Project",
    description="Restore soft-deleted project within retention grace period (FSM T-06). Restricted to OWNER.",
    operation_id="restore_project",
    dependencies=[Depends(require_project_role(ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project restored successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or retention period expired"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Illegal state transition"},
    },
)
async def restore_project(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.restore_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=project,
        message="Project restored successfully",
    )


@router.delete(
    "/{project_id}",
    response_model=ApiResponse[Dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Soft-Delete Project",
    description="Transition project to SOFT_DELETED with retention grace period (FSM T-04, T-05). Restricted to OWNER.",
    operation_id="soft_delete_project",
    dependencies=[Depends(require_project_role(ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project soft-deleted successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Illegal state transition"},
    },
)
async def delete_project(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[Dict[str, str]]:
    project = await project_service.soft_delete_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data={
            "id": str(project.id),
            "status": project.status.value,
            "message": f"Project '{project.name}' soft-deleted successfully",
        },
        message="Project soft-deleted successfully",
    )


@router.delete(
    "/{project_id}/purge",
    response_model=ApiResponse[Dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Permanently Purge Project",
    description="Terminal purge of soft-deleted project (FSM T-07). Cascades cleanup across child collections. Restricted to OWNER.",
    operation_id="purge_project",
    dependencies=[Depends(require_project_role(ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project permanently purged successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Illegal transition (must be soft-deleted first)"},
    },
)
async def purge_project(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[Dict[str, str]]:
    result = await project_service.purge_project(
        identifier=project_id,
        user_id=current_user.clerk_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data={
            "id": project_id,
            "message": str(result.get("message", "Project permanently purged")),
        },
        message="Project permanently purged",
    )


@router.post(
    "/{project_id}/transfer-ownership",
    response_model=ApiResponse[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="Transfer Project Ownership",
    description="Atomic ownership transfer to an active member executed inside a MongoDB transaction (FR-07). Restricted to OWNER.",
    operation_id="transfer_project_ownership",
    dependencies=[Depends(require_project_role(ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Project ownership transferred successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Invalid target or former role"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or target member not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "FSM mutation prohibition"},
    },
)
async def transfer_ownership(
    body: TransferOwnershipRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    project_service: ProjectServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProjectResponse]:
    project = await project_service.transfer_ownership(
        identifier=project_id,
        user_id=current_user.clerk_id,
        data=body,
    )
    return ApiResponse(
        data=project,
        message="Project ownership transferred successfully",
    )


# ------------------------------------------------------------------------------
# 3. Membership & Role Governance
# ------------------------------------------------------------------------------


@router.get(
    "/{project_id}/members",
    response_model=PaginatedResponse[MemberResponse],
    status_code=status.HTTP_200_OK,
    summary="List Project Members",
    description="List members registered in project with pagination. Accessible to all members (VIEWER+).",
    operation_id="list_project_members",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Project members retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
async def list_members(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    member_service: ProjectMemberServiceDep = None,  # type: ignore[assignment]
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
) -> PaginatedResponse[MemberResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await member_service.list_members(
        project_id=project_id,
        user_id=current_user.clerk_id,
        skip=skip,
        limit=effective_page_size,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )

    meta = build_pagination_meta(total_records=total, page=effective_page, page_size=effective_page_size)
    return PaginatedResponse(
        data=PaginatedData(items=items, pagination=meta),
        message="Project members retrieved successfully",
    )


@router.post(
    "/{project_id}/members",
    response_model=ApiResponse[MemberResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Add Project Member",
    description="Add an existing user into the project with an assigned role. Restricted to OWNER or ADMIN.",
    operation_id="add_project_member",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_201_CREATED: {"description": "Member added successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Direct OWNER assignment prohibited"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "User already a member or project archived"},
    },
)
async def add_member(
    body: AddMemberRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    member_service: ProjectMemberServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[MemberResponse]:
    member = await member_service.add_member(
        project_id=project_id,
        actor_id=current_user.clerk_id,
        data=body,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=member,
        message=f"Member '{body.user_id}' added to project successfully",
    )


@router.patch(
    "/{project_id}/members/{user_id}",
    response_model=ApiResponse[MemberResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Member Role",
    description="Modify assigned role of an existing project member. Enforces admin hierarchy boundary.",
    operation_id="update_project_member_role",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Member role updated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Direct OWNER promotion prohibited"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Admin hierarchy violation or altering owner"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or member not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project archived or deleted"},
    },
)
async def update_member_role(
    body: UpdateMemberRoleRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    user_id: str = Path(..., description="Target member Clerk User ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    member_service: ProjectMemberServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[MemberResponse]:
    member = await member_service.update_member_role(
        project_id=project_id,
        actor_id=current_user.clerk_id,
        target_user_id=user_id,
        data=body,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data=member,
        message=f"Role for member '{user_id}' updated to '{body.role.value}' successfully",
    )


@router.delete(
    "/{project_id}/members/{user_id}",
    response_model=ApiResponse[Dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Remove Member / Self-Leave",
    description="Remove a member from project or allow member to voluntarily leave. Enforces sole owner invariant and admin hierarchy.",
    operation_id="remove_project_member",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Member removed successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Sole owner leaving or admin hierarchy violation"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or member not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project archived and caller not self-leaving"},
    },
)
async def remove_member(
    project_id: str = Path(..., description="Project ID or slug"),
    user_id: str = Path(..., description="Target member Clerk User ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    member_service: ProjectMemberServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[Dict[str, str]]:
    result = await member_service.remove_member(
        project_id=project_id,
        actor_id=current_user.clerk_id,
        target_user_id=user_id,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )
    return ApiResponse(
        data={
            "user_id": user_id,
            "message": str(result.get("message", f"Member '{user_id}' removed from project")),
        },
        message="Member removed successfully",
    )


# ------------------------------------------------------------------------------
# 4. Audit Trail
# ------------------------------------------------------------------------------


@router.get(
    "/{project_id}/audit-logs",
    response_model=PaginatedResponse[AuditLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Project Audit Logs",
    description="Retrieve immutable security and state mutation event trail. Restricted to OWNER or ADMIN.",
    operation_id="get_project_audit_logs",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Audit logs retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Insufficient project permissions"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
async def list_audit_logs(
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    audit_service: ProjectAuditServiceDep = None,  # type: ignore[assignment]
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
) -> PaginatedResponse[AuditLogResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await audit_service.list_audit_logs(
        project_id=project_id,
        user_id=current_user.clerk_id,
        skip=skip,
        limit=effective_page_size,
        is_super_admin=(current_user.role == UserRole.ADMIN),
    )

    meta = build_pagination_meta(total_records=total, page=effective_page, page_size=effective_page_size)
    return PaginatedResponse(
        data=PaginatedData(items=items, pagination=meta),
        message="Project audit logs retrieved successfully",
    )
