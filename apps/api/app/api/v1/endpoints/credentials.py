"""
Project Credentials Management API Endpoints (MOD-03) implementing SRS-03.
Provides project-scoped machine credential lifecycle management, CSPRNG key generation,
irreversible SHA-256 hashing, zero-plaintext storage, one-time reveal, OCC updates,
immediate revocation, and cascading purge.
"""
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import (
    CredentialServiceDep,
    CurrentUser,
    require_project_role,
)
from app.models.credential import CredentialStatus
from app.models.project import ProjectRole
from app.schemas.common import (
    ApiErrorResponse,
    ApiResponse,
    PaginatedData,
    PaginatedResponse,
    PaginationParams,
)
from app.schemas.credential import (
    CredentialCreateRequest,
    CredentialCreateResponse,
    CredentialResponse,
    CredentialRevokeRequest,
)
from app.utils.pagination import build_pagination_meta, resolve_pagination

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Credential Listing & Creation (Root Routes)
# ------------------------------------------------------------------------------


@router.post(
    "",
    response_model=ApiResponse[CredentialCreateResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create Project Credential",
    description="Generate a new project API credential. Returns plaintext raw_key strictly once. Zero plaintext is stored in the database.",
    operation_id="create_credential",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_201_CREATED: {"description": "Credential created successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error, empty scopes, or invalid expiration"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Insufficient project permissions"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Credential with name already exists in project, or project is archived"},
    },
)
@router.post(
    "/",
    response_model=ApiResponse[CredentialCreateResponse],
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
)
async def create_credential(
    body: CredentialCreateRequest,
    project_id: str = Path(..., description="Project ID or URL-safe slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    credential_service: CredentialServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[CredentialCreateResponse]:
    created = await credential_service.create_credential(
        project_id=project_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=created,
        message="Credential created successfully. Store the raw_key securely; it will not be shown again.",
    )


@router.get(
    "",
    response_model=PaginatedResponse[CredentialResponse],
    status_code=status.HTTP_200_OK,
    summary="List Project Credentials",
    description="Retrieve a paginated list of credential metadata for a project. Raw keys are never returned.",
    operation_id="list_credentials",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Credentials retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
@router.get(
    "/",
    response_model=PaginatedResponse[CredentialResponse],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
)
async def list_credentials(
    project_id: str = Path(..., description="Project ID or URL-safe slug"),
    environment: Optional[str] = Query(None, description="Filter by environment tier"),
    status_filter: Optional[CredentialStatus] = Query(None, alias="status", description="Filter by status ('active', 'revoked', 'expired')"),
    search: Optional[str] = Query(None, description="Search name or description"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order direction"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    credential_service: CredentialServiceDep = None,  # type: ignore[assignment]
) -> PaginatedResponse[CredentialResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await credential_service.list_credentials(
        project_id=project_id,
        environment=environment,
        status=status_filter,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        skip=skip,
        limit=effective_page_size,
    )

    meta = build_pagination_meta(
        total_records=total,
        page=effective_page,
        page_size=effective_page_size,
    )
    return PaginatedResponse(
        data=PaginatedData(items=items, pagination=meta),
        message="Credentials retrieved successfully",
    )


# ------------------------------------------------------------------------------
# 2. Single Credential Operations (Get, Update, Revoke, Delete)
# ------------------------------------------------------------------------------


@router.get(
    "/{credential_id}",
    response_model=ApiResponse[CredentialResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Credential Metadata",
    description="Retrieve metadata for a single project credential. Raw keys are never returned.",
    operation_id="get_credential",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Credential retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Credential or project not found"},
    },
)
async def get_credential(
    project_id: str = Path(..., description="Project ID or URL-safe slug"),
    credential_id: str = Path(..., description="Credential document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    credential_service: CredentialServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[CredentialResponse]:
    credential = await credential_service.get_credential(
        project_id=project_id,
        credential_id=credential_id,
    )
    return ApiResponse(
        data=credential,
        message="Credential retrieved successfully",
    )


@router.post(
    "/{credential_id}/revoke",
    response_model=ApiResponse[CredentialResponse],
    status_code=status.HTTP_200_OK,
    summary="Revoke Credential",
    description="Immediately revoke an active credential. Subsequent API requests using this key will be rejected.",
    operation_id="revoke_credential",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Credential revoked successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Credential or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Credential already revoked or OCC conflict"},
    },
)
async def revoke_credential(
    body: CredentialRevokeRequest,
    project_id: str = Path(..., description="Project ID or URL-safe slug"),
    credential_id: str = Path(..., description="Credential document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    credential_service: CredentialServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[CredentialResponse]:
    revoked = await credential_service.revoke_credential(
        project_id=project_id,
        credential_id=credential_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=revoked,
        message="Credential revoked successfully",
    )


@router.delete(
    "/{credential_id}",
    response_model=ApiResponse[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Delete or Purge Credential",
    description="Soft-delete (default) or permanently purge (purge=true) a project credential.",
    operation_id="delete_credential",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Credential deleted or purged successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Credential or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Credential already deleted, cannot purge active key, or project archived"},
    },
)
async def delete_credential(
    project_id: str = Path(..., description="Project ID or URL-safe slug"),
    credential_id: str = Path(..., description="Credential document ID"),
    purge: bool = Query(False, description="Set to true for permanent deletion of revoked or soft-deleted key"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    credential_service: CredentialServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[Dict[str, Any]]:
    result = await credential_service.delete_credential(
        project_id=project_id,
        credential_id=credential_id,
        purge=purge,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=result,
        message=result.get("message", "Credential deleted successfully"),
    )
