"""
Provider Management API Endpoints (MOD-06) implementing SRS-06 Section 8.
Provides project-scoped AI model provider registration, zero-plaintext credential binding,
upstream healthchecks, dynamic model discovery, live inspection, and OCC revision control.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import (
    CurrentUser,
    ModelCatalogServiceDep,
    ProviderServiceDep,
    require_project_role,
)
from app.models.project import ProjectRole
from app.models.project_provider import ProviderStatus, ProviderType
from app.schemas.common import (
    ApiErrorResponse,
    ApiResponse,
    PaginatedData,
    PaginatedResponse,
    PaginationParams,
)
from app.schemas.provider import (
    ProviderCreateRequest,
    ProviderDiscoverySummaryResponse,
    ProviderHealthcheckResponse,
    ProviderInspectRequest,
    ProviderInspectResponse,
    ProviderResponse,
    ProviderUpdateRequest,
)
from app.utils.pagination import build_pagination_meta, resolve_pagination

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Provider Listing & Creation
# ------------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[ProviderResponse],
    status_code=status.HTTP_200_OK,
    summary="List Project Providers",
    description="Retrieve a paginated list of model provider configurations and health status for a project. Zero plaintext secrets are returned.",
    operation_id="list_providers",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Providers retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
@router.get(
    "/",
    response_model=PaginatedResponse[ProviderResponse],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
)
async def list_providers(
    project_id: str = Path(..., description="Project 24-char ObjectId hex or URL-safe slug"),
    provider_type: Optional[ProviderType] = Query(None, description="Filter by provider architecture"),
    status_filter: Optional[ProviderStatus] = Query(None, alias="status", description="Filter by operational status"),
    search: Optional[str] = Query(None, description="Search by provider name or slug"),
    sort_by: str = Query("updated_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order direction"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> PaginatedResponse[ProviderResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await provider_service.list_providers(
        project_id=project_id,
        provider_type=provider_type,
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
        message="Providers retrieved successfully",
    )


@router.post(
    "",
    response_model=ApiResponse[ProviderResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register Provider Connection",
    description="Register a new external AI model provider connection bound to a project secret (FR-01, FR-02). Runs live healthcheck test and initializes OCC revision.",
    operation_id="create_provider",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_201_CREATED: {"description": "Provider registered successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or referenced secret not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Provider with slug or name already exists in this project"},
    },
)
@router.post(
    "/",
    response_model=ApiResponse[ProviderResponse],
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
)
async def create_provider(
    body: ProviderCreateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderResponse]:
    created = await provider_service.create_provider(
        project_id=project_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=created,
        message=f"Provider '{created.name}' registered successfully",
    )


# ------------------------------------------------------------------------------
# 2. Live Upstream Inspection (FR-13 Mode 1)
# NOTE: Must be defined before /{provider_id} to avoid path collision
# ------------------------------------------------------------------------------


@router.post(
    "/inspect-models",
    response_model=ApiResponse[ProviderInspectResponse],
    status_code=status.HTTP_200_OK,
    summary="Live Inspect Upstream Provider Models",
    description="Live query upstream provider using in-flight API key or secret_id to preview available models without saving (FR-13 Mode 1).",
    operation_id="inspect_upstream_models",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Upstream models inspected successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Inspection failed or unreachable upstream"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or secret not found"},
    },
)
async def inspect_upstream_models(
    body: ProviderInspectRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderInspectResponse]:
    result = await provider_service.inspect_upstream_models(
        project_id=project_id,
        request=body,
    )
    return ApiResponse(
        data=result,
        message="Upstream models inspected successfully",
    )


# ------------------------------------------------------------------------------
# 3. Single Provider Operations (Inspection, OCC Update, Soft-Delete)
# ------------------------------------------------------------------------------


@router.get(
    "/{provider_id}",
    response_model=ApiResponse[ProviderResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Provider Configuration",
    description="Inspect single provider configuration metadata, connectivity parameters, and latest health status.",
    operation_id="get_provider",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Provider retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
    },
)
async def get_provider(
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderResponse]:
    provider = await provider_service.get_provider(
        project_id=project_id,
        provider_id=provider_id,
    )
    return ApiResponse(
        data=provider,
        message="Provider retrieved successfully",
    )


@router.patch(
    "/{provider_id}",
    response_model=ApiResponse[ProviderResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Provider Configuration",
    description="Update provider metadata, base_url, headers, timeout, or default toggle with OCC revision verification (FR-08).",
    operation_id="update_provider",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Provider updated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "OCC revision mismatch or project archived"},
    },
)
async def update_provider(
    body: ProviderUpdateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderResponse]:
    updated = await provider_service.update_provider(
        project_id=project_id,
        provider_id=provider_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=updated,
        message=f"Provider '{updated.name}' updated successfully",
    )


@router.delete(
    "/{provider_id}",
    response_model=ApiResponse[None],
    status_code=status.HTTP_200_OK,
    summary="Soft-Delete Provider",
    description="Soft-delete a provider and cascade soft-delete all child models (FR-08). Immediately excluded from listings and routing.",
    operation_id="delete_provider",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Provider soft-deleted successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project archived"},
    },
)
async def delete_provider(
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[None]:
    await provider_service.delete_provider(
        project_id=project_id,
        provider_id=provider_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=None,
        message="Provider deleted successfully",
    )


# ------------------------------------------------------------------------------
# 4. Connection Healthcheck & Model Discovery
# ------------------------------------------------------------------------------


@router.post(
    "/{provider_id}/test",
    response_model=ApiResponse[ProviderHealthcheckResponse],
    status_code=status.HTTP_200_OK,
    summary="Test Provider Connection",
    description="Trigger on-demand live connectivity test and latency measurement for an existing provider (FR-03).",
    operation_id="test_provider_connection",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Provider healthcheck completed"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
    },
)
async def test_provider_connection(
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderHealthcheckResponse]:
    result = await provider_service.test_provider_connection(
        project_id=project_id,
        provider_id=provider_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=result,
        message="Provider healthcheck completed",
    )


@router.post(
    "/{provider_id}/discover",
    response_model=ApiResponse[ProviderDiscoverySummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="Discover and Register Upstream Models",
    description="Query upstream provider API and automatically persist discovered models into project catalog (FR-04).",
    operation_id="discover_provider_models",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Models discovered and persisted successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Failed to reach or parse upstream catalog"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
    },
)
async def discover_provider_models(
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderDiscoverySummaryResponse]:
    summary = await model_catalog_service.discover_models(
        project_id=project_id,
        provider_id=provider_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=summary,
        message=f"Discovered {summary.discovered_count} models ({summary.created_count} created, {summary.updated_count} updated)",
    )


@router.get(
    "/{provider_id}/live-models",
    response_model=ApiResponse[ProviderInspectResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Upstream Live Models",
    description="Live query upstream provider using saved provider credentials to view current upstream model catalog (FR-13 Mode 2).",
    operation_id="get_provider_live_models",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Live upstream models retrieved successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Failed to query upstream models"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Provider or project not found"},
    },
)
async def get_provider_live_models(
    project_id: str = Path(..., description="Project ID or slug"),
    provider_id: str = Path(..., description="Provider document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    provider_service: ProviderServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ProviderInspectResponse]:
    result = await provider_service.live_provider_models(
        project_id=project_id,
        provider_id=provider_id,
    )
    return ApiResponse(
        data=result,
        message="Live upstream models retrieved successfully",
    )
