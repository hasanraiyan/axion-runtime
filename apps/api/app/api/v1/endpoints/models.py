"""
Model Catalog API Endpoints (MOD-06) implementing SRS-06 Section 8.
Provides project-scoped AI model catalog management, capability inspection (tools, vision, JSON mode),
manual registration, OCC revision control, and soft deletion.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import (
    CurrentUser,
    ModelCatalogServiceDep,
    require_project_role,
)
from app.models.project import ProjectRole
from app.models.project_model import ModelType
from app.schemas.common import (
    ApiErrorResponse,
    ApiResponse,
    PaginatedData,
    PaginatedResponse,
    PaginationParams,
)
from app.schemas.model_catalog import (
    ModelCreateRequest,
    ModelResponse,
    ModelUpdateRequest,
)
from app.utils.pagination import build_pagination_meta, resolve_pagination

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Model Listing & Creation
# ------------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[ModelResponse],
    status_code=status.HTTP_200_OK,
    summary="List Models in Catalog",
    description="Retrieve a paginated list of registered models filtered by capability flags (tools, vision, JSON mode), provider, or modality (FR-06).",
    operation_id="list_models",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Models retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project not found or caller not a member"},
    },
)
@router.get(
    "/",
    response_model=PaginatedResponse[ModelResponse],
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
)
async def list_models(
    project_id: str = Path(..., description="Project 24-char ObjectId hex or URL-safe slug"),
    provider_id: Optional[str] = Query(None, description="Filter by parent provider ID"),
    model_type: Optional[ModelType] = Query(None, description="Filter by model modality"),
    supports_tools: Optional[bool] = Query(None, description="Filter by tool/function calling support"),
    supports_vision: Optional[bool] = Query(None, description="Filter by vision/multimodal input support"),
    supports_json_mode: Optional[bool] = Query(None, description="Filter by structured JSON output support"),
    is_enabled: Optional[bool] = Query(None, description="Filter by enabled/disabled status"),
    search: Optional[str] = Query(None, description="Search by model identifier or display name"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order direction"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(None, ge=0, description="Offset override"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> PaginatedResponse[ModelResponse]:
    effective_page, effective_page_size = resolve_pagination(
        PaginationParams(page=page, page_size=page_size, limit=limit, offset=offset)
    )
    skip = (effective_page - 1) * effective_page_size

    items, total = await model_catalog_service.list_models(
        project_id=project_id,
        provider_id=provider_id,
        model_type=model_type,
        supports_tools=supports_tools,
        supports_vision=supports_vision,
        supports_json_mode=supports_json_mode,
        is_enabled=is_enabled,
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
        message="Models retrieved successfully",
    )


@router.post(
    "",
    response_model=ApiResponse[ModelResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register Model in Catalog",
    description="Manually register a model under an existing active provider with capability flags and token limits (FR-05).",
    operation_id="create_model",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_201_CREATED: {"description": "Model registered successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Project or parent provider not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Model with identifier already exists for this provider"},
    },
)
@router.post(
    "/",
    response_model=ApiResponse[ModelResponse],
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
)
async def create_model(
    body: ModelCreateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ModelResponse]:
    created = await model_catalog_service.create_model(
        project_id=project_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=created,
        message=f"Model '{created.display_name}' registered successfully",
    )


# ------------------------------------------------------------------------------
# 2. Single Model Operations (Inspection, OCC Update, Soft-Delete)
# ------------------------------------------------------------------------------


@router.get(
    "/{model_id}",
    response_model=ApiResponse[ModelResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Model Capabilities",
    description="Inspect single model definition, capabilities, context limits, and token pricing (FR-06).",
    operation_id="get_model",
    dependencies=[Depends(require_project_role(ProjectRole.VIEWER))],
    responses={
        status.HTTP_200_OK: {"description": "Model retrieved successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Model or project not found"},
    },
)
async def get_model(
    project_id: str = Path(..., description="Project ID or slug"),
    model_id: str = Path(..., description="Model document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ModelResponse]:
    model = await model_catalog_service.get_model(
        project_id=project_id,
        model_id=model_id,
    )
    return ApiResponse(
        data=model,
        message="Model retrieved successfully",
    )


@router.patch(
    "/{model_id}",
    response_model=ApiResponse[ModelResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Model Definition",
    description="Update model capabilities, limits, pricing, or enabled toggle with OCC revision verification (FR-08).",
    operation_id="update_model",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Model updated successfully"},
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse, "description": "Validation error or invalid input"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Model or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "OCC revision mismatch or project archived"},
    },
)
async def update_model(
    body: ModelUpdateRequest,
    project_id: str = Path(..., description="Project ID or slug"),
    model_id: str = Path(..., description="Model document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[ModelResponse]:
    updated = await model_catalog_service.update_model(
        project_id=project_id,
        model_id=model_id,
        request=body,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=updated,
        message=f"Model '{updated.display_name}' updated successfully",
    )


@router.delete(
    "/{model_id}",
    response_model=ApiResponse[None],
    status_code=status.HTTP_200_OK,
    summary="Soft-Delete Model",
    description="Soft-delete a model from catalog (FR-08). Immediately excluded from listings and routing.",
    operation_id="delete_model",
    dependencies=[Depends(require_project_role(ProjectRole.ADMIN, ProjectRole.OWNER))],
    responses={
        status.HTTP_200_OK: {"description": "Model soft-deleted successfully"},
        status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse, "description": "Authentication required"},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse, "description": "Model or project not found"},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse, "description": "Project archived"},
    },
)
async def delete_model(
    project_id: str = Path(..., description="Project ID or slug"),
    model_id: str = Path(..., description="Model document ID"),
    current_user: CurrentUser = None,  # type: ignore[assignment]
    model_catalog_service: ModelCatalogServiceDep = None,  # type: ignore[assignment]
) -> ApiResponse[None]:
    await model_catalog_service.delete_model(
        project_id=project_id,
        model_id=model_id,
        actor_id=current_user.clerk_id,
    )
    return ApiResponse(
        data=None,
        message="Model deleted successfully",
    )
