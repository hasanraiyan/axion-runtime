"""
Integration management endpoints (SRS-07 Section 9.1). HTTP concerns only: parse, call the
service, shape the envelope. All rules live in the services.
"""
from typing import Optional
from fastapi import APIRouter, Path, Query, status

from app.api.v1.endpoints.tools_deps import AdminCaller, ReadCaller, ToolsDep
from app.models.integration import IntegrationStatus, IntegrationType
from app.schemas.common import ApiErrorResponse, ApiResponse, PaginatedData, PaginatedResponse
from app.schemas.tools import (
    DiscoverySummaryResponse,
    EndUserAccessRequest,
    IntegrationCreateRequest,
    IntegrationOnboardingResponse,
    IntegrationResponse,
    IntegrationTypeInfo,
    IntegrationTypesResponse,
    IntegrationUpdateRequest,
    NativeProviderInfo,
    ProbeResponse,
)
from app.services.tools.discovery_service import DiscoverySummary
from app.utils.pagination import build_pagination_meta

router = APIRouter()

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
}


def _summary(summary: DiscoverySummary) -> DiscoverySummaryResponse:
    return DiscoverySummaryResponse(
        added=summary.added,
        changed=summary.changed,
        removed=summary.removed,
        unchanged=summary.unchanged,
        total=summary.total,
        catalog_hash=summary.catalog_hash,
    )


@router.get("/integration-types", response_model=ApiResponse[IntegrationTypesResponse], operation_id="list_integration_types", responses=ERRORS)
async def list_integration_types(project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    types = []
    for key in tools.adapters.keys():
        adapter = tools.adapters.get(key)
        types.append(IntegrationTypeInfo(key=key, supported_auth_types=sorted(a.value for a in adapter.supported_auth_types())))
    natives = [
        NativeProviderInfo(key=p.key, name=p.name, description=p.description, tools=[t.name for t in p.tools])
        for p in tools.native.all()
    ]
    return ApiResponse(data=IntegrationTypesResponse(types=types, native_providers=natives))


@router.post(
    "/integrations",
    response_model=ApiResponse[IntegrationOnboardingResponse],
    status_code=status.HTTP_201_CREATED,
    operation_id="create_integration",
    summary="Create an integration, test it, and discover its tools",
    responses={**ERRORS, status.HTTP_409_CONFLICT: {"model": ApiErrorResponse}},
)
async def create_integration(
    body: IntegrationCreateRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None  # type: ignore[assignment]
):
    result = await tools.onboarding.create_and_verify(caller.project.id, body, caller.actor_id)
    probe = result.probe
    return ApiResponse(
        data=IntegrationOnboardingResponse(
            integration=IntegrationResponse.from_model(result.integration),
            probe=ProbeResponse(
                healthy=probe.healthy,
                status=probe.status,
                latency_ms=probe.latency_ms,
                message=probe.message,
                integration_status=result.integration.status,
                server_info=probe.server_info,
            )
            if probe
            else None,
            discovery=_summary(result.discovery) if result.discovery else None,
            warning=result.warning,
        ),
        message="Integration created",
    )


@router.get("/integrations", response_model=PaginatedResponse[IntegrationResponse], operation_id="list_integrations", responses=ERRORS)
async def list_integrations(
    project_id: str = PID,
    type: Optional[IntegrationType] = Query(None),
    status_filter: Optional[IntegrationStatus] = Query(None, alias="status"),
    search: Optional[str] = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    caller: ReadCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    skip = (page - 1) * page_size
    items, total = await tools.integrations.list(
        caller.project.id, type=type, status=status_filter, search=search, skip=skip, limit=page_size
    )
    return PaginatedResponse(
        data=PaginatedData(
            items=[IntegrationResponse.from_model(i) for i in items],
            pagination=build_pagination_meta(total_records=total, page=page, page_size=page_size),
        ),
        message="Integrations retrieved successfully",
    )


@router.get("/integrations/{integration_id}", response_model=ApiResponse[IntegrationResponse], operation_id="get_integration", responses=ERRORS)
async def get_integration(integration_id: str, project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    doc = await tools.integrations.get(caller.project.id, integration_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc))


@router.patch("/integrations/{integration_id}", response_model=ApiResponse[IntegrationResponse], operation_id="update_integration", responses={**ERRORS, status.HTTP_409_CONFLICT: {"model": ApiErrorResponse}})
async def update_integration(
    integration_id: str, body: IntegrationUpdateRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None  # type: ignore[assignment]
):
    doc = await tools.integrations.update(caller.project.id, integration_id, body, caller.actor_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc), message="Integration updated")


@router.delete("/integrations/{integration_id}", response_model=ApiResponse[IntegrationResponse], operation_id="delete_integration", responses=ERRORS)
async def delete_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    doc = await tools.integrations.delete(caller.project.id, integration_id, caller.actor_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc), message="Integration deleted")


@router.post("/integrations/{integration_id}/restore", response_model=ApiResponse[IntegrationResponse], operation_id="restore_integration", responses=ERRORS)
async def restore_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    doc = await tools.integrations.restore(caller.project.id, integration_id, caller.actor_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc), message="Integration restored")


@router.post("/integrations/{integration_id}/test", response_model=ApiResponse[ProbeResponse], operation_id="test_integration", responses=ERRORS)
async def test_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    integration, probe = await tools.health.test(caller.project.id, integration_id, caller.actor_id)
    return ApiResponse(
        data=ProbeResponse(
            healthy=probe.healthy,
            status=probe.status,
            latency_ms=probe.latency_ms,
            message=probe.message,
            integration_status=integration.status,
            server_info=probe.server_info,
        )
    )


@router.post("/integrations/{integration_id}/discover", response_model=ApiResponse[DiscoverySummaryResponse], operation_id="discover_integration_tools", responses=ERRORS)
async def discover_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    summary = await tools.discovery.discover(caller.project.id, integration_id, caller.actor_id)
    return ApiResponse(data=_summary(summary), message="Discovery completed")


@router.post("/integrations/{integration_id}/enable", response_model=ApiResponse[IntegrationResponse], operation_id="enable_integration", responses=ERRORS)
async def enable_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    doc = await tools.integrations.set_enabled(caller.project.id, integration_id, True, caller.actor_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc))


@router.post("/integrations/{integration_id}/disable", response_model=ApiResponse[IntegrationResponse], operation_id="disable_integration", responses=ERRORS)
async def disable_integration(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    doc = await tools.integrations.set_enabled(caller.project.id, integration_id, False, caller.actor_id)
    return ApiResponse(data=IntegrationResponse.from_model(doc))


@router.put("/integrations/{integration_id}/end-user-access", response_model=ApiResponse[IntegrationResponse], operation_id="set_integration_end_user_access", responses=ERRORS)
async def set_end_user_access(
    integration_id: str, body: EndUserAccessRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None  # type: ignore[assignment]
):
    doc = await tools.integrations.set_end_user_access(
        caller.project.id, integration_id, body.access, body.acknowledge_shared_identity, caller.actor_id
    )
    return ApiResponse(data=IntegrationResponse.from_model(doc), message="End-user access updated")
