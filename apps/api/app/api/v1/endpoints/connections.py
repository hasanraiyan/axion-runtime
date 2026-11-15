"""
Connection endpoints (SRS-07 Section 9.2, 9.6): OAuth connect flows, per-user connections for members and
end users, admin visibility and revocation, and tool policy. HTTP concerns only.

Two endpoints are deliberately public (``/integrations/connect/{token}`` and
``/integrations/oauth/callback``): a browser follows them, so the single-use link secret and the OAuth
``state`` are the credentials. Both answer only with redirects or an outcome, never tokens or codes.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Path, Query, status
from fastapi.responses import RedirectResponse

from app.api.v1.endpoints.tools_deps import AdminCaller, SelfCaller, ToolsDep, caller_dep, make_subject_caller
from app.core.exceptions import ForbiddenError
from app.core.tools.types import Subject, SubjectType
from app.models.project import ProjectRole
from app.schemas.common import ApiErrorResponse, ApiResponse, PaginatedData, PaginatedResponse
from app.schemas.tools import (
    AuthorizeRequest,
    AuthorizeResponse,
    ConnectLinkRequest,
    ConnectLinkResponse,
    ConnectionResponse,
    ConnectOutcomeResponse,
    StaticCredentialRequest,
    ToolPolicyResponse,
    ToolPolicyUpdateRequest,
)
from app.services.tools.principal import role_at_least
from app.utils.pagination import build_pagination_meta

router = APIRouter()

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
}

# Machine credentials with this scope (or admins) manage other subjects' connections and mint connect links.
connections_manage_caller = caller_dep(["connections:manage"], human_min_role=ProjectRole.ADMIN)
member_caller = caller_dep([], human_min_role=ProjectRole.MEMBER, allow_machine=False)


# ================================================================ public browser endpoints
@router.get(
    "/integrations/connect/{token}",
    include_in_schema=True,
    operation_id="open_connect_link",
    summary="Open a single-use connect link",
    description="Public. Redirects the browser to the provider's authorization page. The link is single use.",
    status_code=status.HTTP_302_FOUND,
    responses={status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse}},
)
async def open_connect_link(token: str, tools: ToolsDep = None):  # type: ignore[assignment]
    return RedirectResponse(await tools.connect_flow.begin(token), status_code=status.HTTP_302_FOUND)


@router.get(
    "/integrations/oauth/callback",
    operation_id="oauth_callback",
    summary="OAuth redirect target",
    description="Public. Completes the flow and redirects to the project's return URL (outcome only) when one was set.",
    responses={status.HTTP_302_FOUND: {"description": "Redirect to the return URL"}},
)
async def oauth_callback(
    state: Optional[str] = Query(None, max_length=512),
    code: Optional[str] = Query(None, max_length=4096),
    error: Optional[str] = Query(None, max_length=200),
    iss: Optional[str] = Query(None, max_length=2000),
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    outcome = await tools.connect_flow.complete(state, code, error, iss)
    target = outcome.redirect_target()
    if target:
        return RedirectResponse(target, status_code=status.HTTP_302_FOUND)
    return ApiResponse(
        data=ConnectOutcomeResponse(success=outcome.success, integration=outcome.integration_slug, error=outcome.error),
        message="Connected" if outcome.success else "Connection failed",
    )


# ================================================================== admin / machine
@router.post(
    "/projects/{project_id}/integrations/{integration_id}/oauth/authorize",
    response_model=ApiResponse[AuthorizeResponse],
    operation_id="authorize_integration",
    summary="Start connecting the signed-in member (or the project's shared credential)",
    responses=ERRORS,
)
async def authorize_integration(
    integration_id: str, body: Optional[AuthorizeRequest] = None, project_id: str = PID,
    caller=Depends(member_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    body = body or AuthorizeRequest()
    if body.scope == "project":
        if not role_at_least(caller.role, ProjectRole.ADMIN):
            raise ForbiddenError("Only admins can connect the project's shared credential")
        subject = Subject(SubjectType.PROJECT)
    else:
        subject = Subject(SubjectType.MEMBER, id=caller.actor_id)
    url = await tools.connect_flow.start_authorization(caller.project.id, integration_id, subject, body.return_url, caller.actor_id)
    return ApiResponse(data=AuthorizeResponse(authorization_url=url))


@router.post(
    "/projects/{project_id}/integrations/{integration_id}/connect-links",
    response_model=ApiResponse[ConnectLinkResponse],
    status_code=status.HTTP_201_CREATED,
    operation_id="create_connect_link",
    summary="Create a single-use link for one end user or member to connect their own account",
    responses=ERRORS,
)
async def create_connect_link(
    integration_id: str, body: ConnectLinkRequest, project_id: str = PID,
    caller=Depends(connections_manage_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    if bool(body.end_user_external_id) == bool(body.member_id):
        from app.core.exceptions import BadRequestError

        raise BadRequestError("Provide exactly one of end_user_external_id or member_id")
    if body.end_user_external_id:
        subject = await tools.end_users.resolve_subject(caller.project.id, body.end_user_external_id, caller.actor_id)
    else:
        subject = Subject(SubjectType.MEMBER, id=body.member_id)
    url, ttl = await tools.connect_flow.create_link(caller.project.id, integration_id, subject, body.return_url, caller.actor_id)
    return ApiResponse(data=ConnectLinkResponse(connect_url=url, expires_in=ttl), message="Connect link created")


@router.get(
    "/projects/{project_id}/integrations/{integration_id}/connections",
    response_model=PaginatedResponse[ConnectionResponse],
    operation_id="list_integration_connections",
    summary="Connection metadata for an integration (never credentials)",
    responses=ERRORS,
)
async def list_connections(
    integration_id: str, project_id: str = PID, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
    caller=Depends(connections_manage_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    items, total = await tools.connections.list_for_integration(caller.project.id, integration_id, skip=(page - 1) * page_size, limit=page_size)
    return PaginatedResponse(
        data=PaginatedData(
            items=[ConnectionResponse.from_model(c) for c in items],
            pagination=build_pagination_meta(total_records=total, page=page, page_size=page_size),
        ),
        message="Connections retrieved successfully",
    )


@router.delete(
    "/projects/{project_id}/integrations/{integration_id}/connections/{connection_id}",
    response_model=ApiResponse[dict],
    operation_id="revoke_integration_connection",
    summary="Revoke a connection (the credential is deleted; it is never shown)",
    responses=ERRORS,
)
async def revoke_connection(
    integration_id: str, connection_id: str, project_id: str = PID,
    caller=Depends(connections_manage_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    await tools.connections.revoke(caller.project.id, integration_id, connection_id, caller.actor_id)
    return ApiResponse(data={"revoked": True}, message="Connection revoked")


@router.get("/projects/{project_id}/tool-policy", response_model=ApiResponse[ToolPolicyResponse], operation_id="get_tool_policy", responses=ERRORS)
async def get_tool_policy(project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    return ApiResponse(data=ToolPolicyResponse.from_model(await tools.policy.get(caller.project.id)))


@router.patch("/projects/{project_id}/tool-policy", response_model=ApiResponse[ToolPolicyResponse], operation_id="update_tool_policy", responses=ERRORS)
async def update_tool_policy(body: ToolPolicyUpdateRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    updated = await tools.policy.update(
        caller.project.id, body.revision, caller.actor_id,
        allowed_return_origins=body.allowed_return_origins,
        end_user_connect_enabled=body.end_user_connect_enabled,
        connect_link_ttl_seconds=body.connect_link_ttl_seconds,
        default_approval_policy=body.default_approval_policy,
        invocation_content_retention_days=body.invocation_content_retention_days,
        end_user_default_rate_limit_per_minute=body.end_user_default_rate_limit_per_minute,
    )
    return ApiResponse(data=ToolPolicyResponse.from_model(updated), message="Tool policy updated")


# ================================================================ self-service (member or end user)
self_caller = make_subject_caller("connections:own")


@router.get(
    "/projects/{project_id}/me/connections",
    response_model=ApiResponse[list[ConnectionResponse]],
    operation_id="list_my_connections",
    summary="The caller's own connections",
    responses=ERRORS,
)
async def list_my_connections(project_id: str = PID, who: SelfCaller = Depends(self_caller), tools: ToolsDep = None):  # type: ignore[assignment]
    rows = await tools.connections.list_for_subject(who.project.id, who.subject)
    return ApiResponse(data=[ConnectionResponse.from_model(c, i) for c, i in rows])


@router.post(
    "/projects/{project_id}/me/connections/{integration_id}/oauth",
    response_model=ApiResponse[AuthorizeResponse],
    operation_id="start_my_oauth_connection",
    summary="Start connecting the caller's own account",
    responses=ERRORS,
)
async def start_my_oauth(
    integration_id: str, body: Optional[AuthorizeRequest] = None, project_id: str = PID,
    who: SelfCaller = Depends(self_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    url = await tools.connect_flow.start_authorization(
        who.project.id, integration_id, who.subject, (body.return_url if body else None), who.actor_id
    )
    return ApiResponse(data=AuthorizeResponse(authorization_url=url))


@router.put(
    "/projects/{project_id}/me/connections/{integration_id}/credential",
    response_model=ApiResponse[ConnectionResponse],
    operation_id="set_my_credential",
    summary="Store the caller's own API key or token for a per-user integration",
    description="The value is verified against the service, stored encrypted, and never returned.",
    responses=ERRORS,
)
async def set_my_credential(
    integration_id: str, body: StaticCredentialRequest, project_id: str = PID,
    who: SelfCaller = Depends(self_caller), tools: ToolsDep = None,  # type: ignore[assignment]
):
    connection = await tools.connect_flow.connect_static(
        who.project.id, integration_id, who.subject, body.credential.get_secret_value(), who.actor_id
    )
    return ApiResponse(data=ConnectionResponse.from_model(connection), message="Connected")


@router.delete(
    "/projects/{project_id}/me/connections/{integration_id}",
    response_model=ApiResponse[dict],
    operation_id="disconnect_my_connection",
    summary="Disconnect the caller's own connection",
    responses=ERRORS,
)
async def disconnect_mine(
    integration_id: str, project_id: str = PID, who: SelfCaller = Depends(self_caller), tools: ToolsDep = None  # type: ignore[assignment]
):
    removed = await tools.connections.disconnect(who.project.id, integration_id, who.subject, who.actor_id, reason="self_disconnect")
    return ApiResponse(data={"disconnected": removed}, message="Disconnected" if removed else "No connection to remove")
