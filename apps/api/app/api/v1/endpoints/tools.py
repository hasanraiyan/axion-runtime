"""Tool catalog, tool settings, bindings, and invocation history endpoints (SRS-07 Section 9.3)."""
from typing import Optional
from fastapi import APIRouter, Path, Query, status

from app.api.v1.endpoints.tools_deps import AdminCaller, AuditCaller, ReadCaller, ToolsDep
from app.models.tool import BindingSubjectType, ToolSyncState
from app.models.tool_invocation import InvocationStatus
from app.schemas.common import ApiErrorResponse, ApiResponse, PaginatedData, PaginatedResponse
from app.schemas.tools import (
    ToolBulkRequest,
    ToolBulkResponse,
    BindingReplaceRequest,
    BindingResponse,
    InvocationRecordResponse,
    ToolResponse,
    ToolSettingUpdateRequest,
)
from app.utils.pagination import build_pagination_meta

router = APIRouter()

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
    status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
}


@router.get("/tools", response_model=PaginatedResponse[ToolResponse], operation_id="list_tools", responses=ERRORS)
async def list_tools(
    project_id: str = PID,
    integration_id: Optional[str] = Query(None),
    sync_state: Optional[ToolSyncState] = Query(None),
    search: Optional[str] = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    caller: ReadCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    skip = (page - 1) * page_size
    pairs, total = await tools.catalog.list_tools(
        caller.project.id, integration_id=integration_id, sync_state=sync_state, search=search, skip=skip, limit=page_size
    )
    return PaginatedResponse(
        data=PaginatedData(
            items=[ToolResponse.from_models(d, s) for d, s in pairs],
            pagination=build_pagination_meta(total_records=total, page=page, page_size=page_size),
        ),
        message="Tools retrieved successfully",
    )


@router.post("/tools/bulk", response_model=ApiResponse[ToolBulkResponse], operation_id="bulk_update_tools", summary="Enable, disable, or set the approval policy of many tools", description="Reports the outcome per tool. Enabling approves each tool's current definition; drifted tools are skipped, never silently approved.", responses=ERRORS)
async def bulk_update_tools(body: ToolBulkRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    return ApiResponse(data=await tools.tool_settings.bulk_update(caller.project.id, body, caller.actor_id), message="Bulk update processed")


@router.get("/tools/{tool_key}", response_model=ApiResponse[ToolResponse], operation_id="get_tool", responses=ERRORS)
async def get_tool(tool_key: str, project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    definition, setting = await tools.catalog.get_tool(caller.project.id, tool_key)
    return ApiResponse(data=ToolResponse.from_models(definition, setting))


@router.patch("/tools/{tool_key}", response_model=ApiResponse[ToolResponse], operation_id="update_tool_setting", responses=ERRORS)
async def update_tool_setting(
    tool_key: str, body: ToolSettingUpdateRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None  # type: ignore[assignment]
):
    definition, setting = await tools.tool_settings.update(caller.project.id, tool_key, body, caller.actor_id)
    return ApiResponse(data=ToolResponse.from_models(definition, setting), message="Tool updated")


@router.post("/tools/{tool_key}/approve", response_model=ApiResponse[ToolResponse], operation_id="approve_tool", responses=ERRORS)
async def approve_tool(tool_key: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    definition, setting = await tools.tool_settings.approve(caller.project.id, tool_key, caller.actor_id)
    return ApiResponse(data=ToolResponse.from_models(definition, setting), message="Tool definition approved")


@router.get("/tool-bindings", response_model=ApiResponse[list[BindingResponse]], operation_id="list_tool_bindings", responses=ERRORS)
async def list_bindings(
    project_id: str = PID,
    subject_type: Optional[BindingSubjectType] = Query(None),
    subject_id: Optional[str] = Query(None, max_length=200),
    caller: ReadCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    items = await tools.bindings.list(caller.project.id, subject_type=subject_type, subject_id=subject_id)
    return ApiResponse(data=[BindingResponse.from_model(b) for b in items])


@router.put("/tool-bindings", response_model=ApiResponse[list[BindingResponse]], operation_id="replace_tool_bindings", responses=ERRORS)
async def replace_bindings(
    body: BindingReplaceRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None  # type: ignore[assignment]
):
    items = await tools.bindings.replace(caller.project.id, body, caller.actor_id)
    return ApiResponse(data=[BindingResponse.from_model(b) for b in items], message="Bindings replaced")


@router.get("/tool-invocations", response_model=PaginatedResponse[InvocationRecordResponse], operation_id="list_tool_invocations", responses=ERRORS)
async def list_invocations(
    project_id: str = PID,
    tool_key: Optional[str] = Query(None, max_length=160),
    status_filter: Optional[InvocationStatus] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    caller: AuditCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    items, total = await tools.invocations.list_by_project(
        caller.project.id, tool_key=tool_key, status=status_filter, skip=(page - 1) * page_size, limit=page_size
    )
    return PaginatedResponse(
        data=PaginatedData(
            items=[InvocationRecordResponse.from_model(i) for i in items],
            pagination=build_pagination_meta(total_records=total, page=page, page_size=page_size),
        ),
        message="Invocations retrieved successfully",
    )
