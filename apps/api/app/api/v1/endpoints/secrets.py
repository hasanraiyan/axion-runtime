"""
Secrets Management API Endpoints (MOD-02) implementing SRS-02 Section 7.1, 7.2, 8.1.
Provides project-scoped secret lifecycle management, AES-256-GCM envelope encryption,
zero-plaintext persistence, OCC revision control, privileged reveal, and runtime resolution.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Path, Query, Request, Response, status

from app.api.deps import (
    CurrentUser,
    SecretResolverDep,
    SecretServiceDep,
    require_project_role,
)
from app.models.project import ProjectRole
from app.schemas.common import (
    ApiErrorResponse,
    ApiResponse,
    PaginatedData,
    PaginatedResponse,
    PaginationParams,
)
from app.schemas.secret import (
    SecretBatchResolveRequest,
    SecretBatchResolveResponse,
    SecretCreateRequest,
    SecretResponse,
    SecretRevealRequest,
    SecretRotateRequest,
    SecretSummaryResponse,
    SecretUpdateRequest,
    SecretValueResponse,
)
from app.utils.pagination import build_pagination_meta, resolve_pagination

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Secret Listing & Creation (Root Routes)
# ------------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[SecretSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="List Secret Metadata",
    description="Retrieve a paginated list of secret metadata for a project. Zero plaintext or ciphertext is returned.",
    operation_id="list_secrets",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Secrets retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
@router.get(
    "/",
    response_model=PaginatedResponse[SecretSummaryResponse],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
)
async def list_secrets(
    project_id: str = Path(..., description="Project 24-char ObjectId hex or URL-safe slug"),
    environment: Optional[str] = Query(None, description="Filter secrets by execution environment"),
    search: Optional[str] = Query(None, description="Search secret name or description"),
    tags: Optional[List[str]] = Query(None, description="Filter by categorization tags"),
    sort_by: str = Query("updated_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order direction"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> PaginatedResponse[SecretSummaryResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await secret_service.list_secrets(
        project_id=project_id,
        environment=environment,
        search=search,
        tags=tags,
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
        message="Secrets retrieved successfully",
    )


@router.post(
    "",
    response_model=ApiResponse[SecretResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create Secret",
    description="Create and envelope-encrypt a new project secret. Returns metadata only; zero plaintext is returned.",
    operation_id="create_secret",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_201_CREATED: {"description": "Secret created successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Secret with name already exists in environment, or project is archived"},
    },
)
@router.post(
    "/",
    response_model=ApiResponse[SecretResponse],
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
)
async def create_secret(
    body: SecretCreateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretResponse]:
    created = await secret_service.create_secret(
        project_id=project_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=created,
        message=f"Secret '{created.name}' created successfully",
    )


# ------------------------------------------------------------------------------
# 2. Runtime Secret Resolution
# ------------------------------------------------------------------------------


@router.post(
    "/resolve",
    response_model=ApiResponse[SecretBatchResolveResponse],
    status_code=status.HTTP_200_OK,
    summary="Batch Resolve Runtime Secrets",
    description="Batch resolve decrypted plaintext secrets for runtime sandboxes and workflow execution nodes.",
    operation_id="batch_resolve_secrets",
    dependencies=[Depends(require_project_role(ProjectRole.MEMBER, ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Secrets resolved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Insufficient permissions (requires MEMBER+)"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project is archived or inactive"},
    },
)
async def batch_resolve_secrets(
    body: SecretBatchResolveRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_resolver: SecretResolverDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretBatchResolveResponse]:
    result = await secret_resolver.resolve_secrets(
        project_id=project_id,
        names=body.names,
        environment=body.environment,
        execution_id=body.execution_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=result,
        message="Secrets resolved successfully",
    )


# ------------------------------------------------------------------------------
# 3. Single Secret Inspection, Mutation, and Lifecycle Operations
# ------------------------------------------------------------------------------


@router.get(
    "/{secret_id}",
    response_model=ApiResponse[SecretResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Secret Metadata",
    description="Retrieve metadata for a single project secret. Zero plaintext or ciphertext is returned.",
    operation_id="get_secret_metadata",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Secret metadata retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Secret or project not found"},
    },
)
async def get_secret(
    project_id: str = Path(..., description="Project ID or slug"),
    secret_id: str = Path(..., description="Secret document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretResponse]:
    secret = await secret_service.get_secret_metadata(
        project_id=project_id,
        secret_id=secret_id,
    )
    return ApiResponse(
        data=secret,
        message="Secret metadata retrieved successfully",
    )


@router.put(
    "/{secret_id}",
    response_model=ApiResponse[SecretResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Secret with OCC",
    description="In-place update of secret metadata or value with Optimistic Concurrency Control revision verification.",
    operation_id="update_secret",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Secret updated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Secret or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "OCC revision mismatch or project archived"},
    },
)
async def update_secret(
    body: SecretUpdateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    secret_id: str = Path(..., description="Secret document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretResponse]:
    updated = await secret_service.update_secret(
        project_id=project_id,
        secret_id=secret_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=updated,
        message="Secret updated successfully",
    )


@router.delete(
    "/{secret_id}",
    response_model=ApiResponse[None],
    status_code=status.HTTP_200_OK,
    summary="Soft-Delete Secret",
    description="Soft delete a secret. Immediately excludes it from listings and runtime resolution.",
    operation_id="delete_secret",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Secret soft-deleted successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Secret or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project archived"},
    },
)
async def delete_secret(
    project_id: str = Path(..., description="Project ID or slug"),
    secret_id: str = Path(..., description="Secret document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[None]:
    await secret_service.delete_secret(
        project_id=project_id,
        secret_id=secret_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=None,
        message="Secret deleted successfully",
    )


@router.post(
    "/{secret_id}/reveal",
    response_model=ApiResponse[SecretValueResponse],
    status_code=status.HTTP_200_OK,
    summary="Privileged Reveal Secret Value",
    description="Privileged plaintext reveal for project administrators (OWNER, ADMIN). Decrypts in-memory, emits immutable audit log, and sets non-cacheable headers.",
    operation_id="reveal_secret_value",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Secret revealed successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse, "description": "Forbidden (VIEWER and MEMBER cannot reveal secret plaintext)"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Secret or project not found"},
    },
)
async def reveal_secret(
    request: Request,
    response: Response,
    project_id: str = Path(..., description="Project ID or slug"),
    secret_id: str = Path(..., description="Secret document ID"),
    body: Optional[SecretRevealRequest] = None,
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretValueResponse]:
    # Set strict anti-caching HTTP headers per SRS Section 7.1
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    reason = body.reason if body else None

    revealed = await secret_service.reveal_secret_value(
        project_id=project_id,
        secret_id=secret_id,
        actor_id=current_user.clerk_id,
        reason=reason,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ApiResponse(
        data=revealed,
        message="Secret revealed successfully",
    )


@router.post(
    "/{secret_id}/rotate",
    response_model=ApiResponse[SecretResponse],
    status_code=status.HTTP_200_OK,
    summary="Rotate Secret Value",
    description="In-place rotation of secret value with fresh DEK/nonce generation and OCC revision check.",
    operation_id="rotate_secret",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Secret rotated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Secret or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "OCC revision mismatch or project archived"},
    },
)
async def rotate_secret(
    body: SecretRotateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    secret_id: str = Path(..., description="Secret document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    secret_service: SecretServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[SecretResponse]:
    rotated = await secret_service.rotate_secret(
        project_id=project_id,
        secret_id=secret_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=rotated,
        message="Secret rotated successfully",
    )
