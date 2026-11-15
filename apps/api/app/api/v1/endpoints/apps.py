"""
MCP resources, prompts, and MCP App endpoints (SRS-07 Section 9.3, 9.4, FR-45..FR-51). HTTP concerns only.

An app is third-party code: the content endpoint refuses anything not approved at its *current* hash, the bridge
endpoints accept only an approved app's own integration, and every bridged tool call goes through the gateway.
"""
from fastapi import APIRouter, Depends, Path, Response, status

from app.api.v1.endpoints.tool_runtime import to_invoke_response
from app.api.v1.endpoints.tools_deps import AdminCaller, ReadCaller, SelfCaller, ToolsDep, make_subject_caller
from app.core.tools.types import Actor, ActorType, PrincipalContext, Subject, SubjectType
from app.schemas.common import ApiErrorResponse, ApiResponse
from app.schemas.tools import (
    AppApproveRequest,
    AppContentResponse,
    AppResourceReadRequest,
    AppResourceResponse,
    AppSyncResponse,
    AppToolCallRequest,
    InvokeResponse,
    PromptInfoResponse,
    ResourceInfoResponse,
    ResourceReadResponse,
)

router = APIRouter()

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
    status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
}

app_caller = make_subject_caller("apps:use")


def _subject_of(caller) -> Subject:
    return Subject(SubjectType.MEMBER, id=caller.actor_id) if caller.is_human else Subject(SubjectType.PROJECT)


# ================================================================ resources & prompts (admins, viewers)
@router.get("/integrations/{integration_id}/resources", response_model=ApiResponse[list[ResourceInfoResponse]], operation_id="list_integration_resources", responses=ERRORS)
async def list_resources(integration_id: str, project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    items = await tools.apps.list_resources(caller.project.id, integration_id, _subject_of(caller))
    return ApiResponse(data=[ResourceInfoResponse(uri=r.uri, name=r.name, description=r.description, mime_type=r.mime_type, is_template=r.is_template) for r in items])


@router.get("/integrations/{integration_id}/prompts", response_model=ApiResponse[list[PromptInfoResponse]], operation_id="list_integration_prompts", responses=ERRORS)
async def list_prompts(integration_id: str, project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    items = await tools.apps.list_prompts(caller.project.id, integration_id, _subject_of(caller))
    return ApiResponse(data=[PromptInfoResponse(name=p.name, description=p.description, arguments=p.arguments) for p in items])


# ================================================================ app lifecycle (admins)
@router.get("/integrations/{integration_id}/apps", response_model=ApiResponse[list[AppResourceResponse]], operation_id="list_integration_apps", responses=ERRORS)
async def list_apps(integration_id: str, project_id: str = PID, caller: ReadCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    items = await tools.apps.list_apps(caller.project.id, integration_id)
    return ApiResponse(data=[AppResourceResponse.from_model(i) for i in items])


@router.post("/integrations/{integration_id}/apps/sync", response_model=ApiResponse[AppSyncResponse], operation_id="sync_integration_apps", summary="Fetch and hash-pin the app resources the integration's tools reference", responses=ERRORS)
async def sync_apps(integration_id: str, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    summary = await tools.apps.sync_integration(caller.project.id, integration_id, caller.actor_id, subject=_subject_of(caller))
    return ApiResponse(data=AppSyncResponse(synced=summary.synced, changed=summary.changed, unavailable=summary.unavailable), message="Apps synced")


@router.post("/app-resources/{resource_id}/approve", response_model=ApiResponse[AppResourceResponse], operation_id="approve_app_resource", summary="Approve one exact version of an app, with specific domains and permissions", responses=ERRORS)
async def approve_app(resource_id: str, body: AppApproveRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    updated = await tools.apps.approve(caller.project.id, resource_id, body.content_hash, body.csp, body.permissions, caller.actor_id)
    return ApiResponse(data=AppResourceResponse.from_model(updated), message="App approved")


# ================================================================ rendering and the bridge (members, end users)
@router.get("/app-resources/{resource_id}/content", response_model=ApiResponse[AppContentResponse], operation_id="get_app_content", summary="Approved HTML with its approved domains and permissions", description="Refuses unapproved or changed apps. The host must apply exactly the returned CSP and permissions.", responses=ERRORS)
async def get_app_content(
    resource_id: str, response: Response, project_id: str = PID,
    who: SelfCaller = Depends(app_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    app = await tools.apps.render(who.project.id, resource_id, who.subject)
    response.headers["Cache-Control"] = "no-store"
    return ApiResponse(
        data=AppContentResponse(
            resource_id=app.resource_id, uri=app.uri, mime_type=app.mime_type, html=app.html,
            content_hash=app.content_hash, csp=app.csp, permissions=app.permissions,
        )
    )


@router.post("/apps/tool-calls", response_model=ApiResponse[InvokeResponse], operation_id="app_call_tool", summary="A tool call made by an approved app", description="Same integration only, tools that declare the app as a caller only, and the full gateway pipeline.", responses=ERRORS)
async def app_tool_call(
    body: AppToolCallRequest, project_id: str = PID, who: SelfCaller = Depends(app_caller), tools: ToolsDep = None  # type: ignore[assignment]
):
    principal = PrincipalContext(
        project_id=str(who.project.id),
        actor=Actor(ActorType.USER if who.subject.type == SubjectType.MEMBER else ActorType.MACHINE, who.actor_id),
        subject=who.subject,
        origin="app_widget",
        member_role=who.role.value if who.role else None,
    )
    result = await tools.apps.call_tool(principal, body.resource_id, body.tool_key, body.arguments, body.idempotency_key)
    return ApiResponse(data=to_invoke_response(result), message="Tool invocation processed")


@router.post("/apps/resource-reads", response_model=ApiResponse[ResourceReadResponse], operation_id="app_read_resource", summary="A resource read made by an approved app", responses=ERRORS)
async def app_resource_read(
    body: AppResourceReadRequest, project_id: str = PID, who: SelfCaller = Depends(app_caller), tools: ToolsDep = None  # type: ignore[assignment]
):
    fetched = await tools.apps.read_resource(who.project.id, who.subject, body.resource_id, body.uri)
    return ApiResponse(data=ResourceReadResponse(uri=fetched.uri, mime_type=fetched.mime_type, text=fetched.text, blob_base64=fetched.blob_base64, size_bytes=fetched.size_bytes))

