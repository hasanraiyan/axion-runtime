"""End-user endpoints (SRS-07 Section 9.6): assertion, management, and session tokens (FR-70, 71, 79)."""
from typing import Annotated, Optional
from fastapi import APIRouter, Path, Query, Security, status

from app.api.deps import end_user_token_scheme
from app.api.v1.endpoints.tools_deps import EndUserAssertCaller, EndUserManageCaller, ToolsDep
from app.core.exceptions import UnauthorizedError
from app.models.end_user import EndUserStatus
from app.schemas.common import ApiErrorResponse, ApiResponse, PaginatedData, PaginatedResponse
from app.schemas.tools import (
    EndUserAssertRequest,
    EndUserResponse,
    EndUserSessionRequest,
    EndUserSessionResponse,
)
from app.utils.pagination import build_pagination_meta

router = APIRouter()

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
}


@router.put("/end-users/{external_id}", response_model=ApiResponse[EndUserResponse], operation_id="assert_end_user", responses=ERRORS)
async def assert_end_user(
    external_id: str,
    body: Optional[EndUserAssertRequest] = None,
    project_id: str = PID,
    caller: EndUserAssertCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    user, created = await tools.end_users.assert_user(caller.project.id, external_id, body, caller.actor_id)
    return ApiResponse(data=EndUserResponse.from_model(user), message="End user created" if created else "End user updated")


@router.get("/end-users", response_model=PaginatedResponse[EndUserResponse], operation_id="list_end_users", responses=ERRORS)
async def list_end_users(
    project_id: str = PID,
    status_filter: Optional[EndUserStatus] = Query(None, alias="status"),
    search: Optional[str] = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    caller: EndUserManageCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    items, total = await tools.end_users.list(
        caller.project.id, status=status_filter, search=search, skip=(page - 1) * page_size, limit=page_size
    )
    return PaginatedResponse(
        data=PaginatedData(
            items=[EndUserResponse.from_model(u) for u in items],
            pagination=build_pagination_meta(total_records=total, page=page, page_size=page_size),
        ),
        message="End users retrieved successfully",
    )


@router.get("/end-users/{external_id}", response_model=ApiResponse[EndUserResponse], operation_id="get_end_user", responses=ERRORS)
async def get_end_user(external_id: str, project_id: str = PID, caller: EndUserManageCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    return ApiResponse(data=EndUserResponse.from_model(await tools.end_users.get(caller.project.id, external_id)))


@router.post("/end-users/{external_id}/block", response_model=ApiResponse[EndUserResponse], operation_id="block_end_user", responses=ERRORS)
async def block_end_user(external_id: str, project_id: str = PID, caller: EndUserManageCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    user = await tools.end_users.block(caller.project.id, external_id, caller.actor_id)
    return ApiResponse(data=EndUserResponse.from_model(user), message="End user blocked")


@router.post("/end-users/{external_id}/unblock", response_model=ApiResponse[EndUserResponse], operation_id="unblock_end_user", responses=ERRORS)
async def unblock_end_user(external_id: str, project_id: str = PID, caller: EndUserManageCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    user = await tools.end_users.unblock(caller.project.id, external_id, caller.actor_id)
    return ApiResponse(data=EndUserResponse.from_model(user), message="End user unblocked")


@router.delete("/end-users/{external_id}", response_model=ApiResponse[dict], operation_id="delete_end_user", responses=ERRORS)
async def delete_end_user(external_id: str, project_id: str = PID, caller: EndUserManageCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    await tools.end_users.delete(caller.project.id, external_id, caller.actor_id)
    return ApiResponse(data={"deleted": True}, message="End user erased")


@router.post(
    "/end-users/{external_id}/sessions",
    response_model=ApiResponse[EndUserSessionResponse],
    status_code=status.HTTP_201_CREATED,
    operation_id="create_end_user_session",
    summary="Mint a short-lived session token for one end user",
    responses=ERRORS,
)
async def create_end_user_session(
    external_id: str,
    body: Optional[EndUserSessionRequest] = None,
    project_id: str = PID,
    caller: EndUserAssertCaller = None,  # type: ignore[assignment]
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    body = body or EndUserSessionRequest()
    token, end_user_id = await tools.end_users.mint_session(
        caller.project.id, external_id, body.ttl_seconds, body.capabilities, caller.actor_id
    )
    return ApiResponse(
        data=EndUserSessionResponse(token=token, expires_in=body.ttl_seconds, end_user_id=end_user_id),
        message="Session created",
    )


@router.get("/me", response_model=ApiResponse[EndUserResponse], operation_id="get_current_end_user", responses=ERRORS)
async def get_current_end_user(
    project_id: str = PID,
    x_axion_end_user_token: Annotated[Optional[str], Security(end_user_token_scheme)] = None,
    tools: ToolsDep = None,  # type: ignore[assignment]
):
    """Who am I? Authenticated by an end-user session token (no Clerk account needed)."""
    if not x_axion_end_user_token:
        raise UnauthorizedError("Missing end-user session token")
    claims = await tools.end_users.verify_session(x_axion_end_user_token, project_id)
    user = await tools.end_users.get(project_id, str(claims.get("ext")))
    return ApiResponse(data=EndUserResponse.from_model(user))
