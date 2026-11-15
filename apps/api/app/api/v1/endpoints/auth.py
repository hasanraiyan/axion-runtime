from fastapi import APIRouter, Depends, Path, Request, Response, status
from app.api.deps import CurrentAdmin, CurrentUser
from app.schemas.auth import AuthenticatedUser, UpdateUserRoleRequest, UpdateUserStatusRequest
from app.schemas.common import ApiErrorResponse, ApiResponse
from app.services.user_service import UserService, get_user_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get(
    "/me",
    response_model=ApiResponse[AuthenticatedUser],
    status_code=status.HTTP_200_OK,
    summary="Get Authenticated User",
    description="Retrieve the current verified Clerk user profile, MongoDB sync state, and assigned role.",
    operation_id="get_current_authenticated_user",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ApiErrorResponse,
            "description": "Missing, expired, or invalid authorization token",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ApiErrorResponse,
            "description": "Account is disabled",
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "model": ApiErrorResponse,
            "description": "Rate limit exceeded",
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": ApiErrorResponse,
            "description": "Database service unavailable",
        },
    },
)
async def get_me(
    current_user: CurrentUser,
    response: Response,
) -> ApiResponse[AuthenticatedUser]:
    # Prevent caching of personal identity data by proxies or browsers (AUTH-11)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return ApiResponse(
        data=current_user,
        message="Authenticated user profile retrieved successfully",
    )


@router.put(
    "/users/{clerk_id}/role",
    response_model=ApiResponse[AuthenticatedUser],
    status_code=status.HTTP_200_OK,
    summary="Update User Role",
    description="Update the authorization role of a user ('admin' or 'user'). Requires admin role.",
    operation_id="update_user_role",
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ApiErrorResponse,
            "description": "Target user is inactive or request is invalid",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ApiErrorResponse,
            "description": "Missing or invalid authorization token",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ApiErrorResponse,
            "description": "Admin privileges required or account disabled",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ApiErrorResponse,
            "description": "Target user not found",
        },
        status.HTTP_409_CONFLICT: {
            "model": ApiErrorResponse,
            "description": "Cannot demote self or the last remaining administrator",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ApiErrorResponse,
            "description": "Malformed role value or path parameter",
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "model": ApiErrorResponse,
            "description": "Rate limit exceeded",
        },
    },
)
async def update_user_role(
    request: Request,
    body: UpdateUserRoleRequest,
    _admin: CurrentAdmin,
    clerk_id: str = Path(..., pattern=r"^user_[A-Za-z0-9]+$", description="Target Clerk User ID"),
    user_service: UserService = Depends(get_user_service),
) -> ApiResponse[AuthenticatedUser]:
    request_id = request.headers.get("x-request-id")
    ip_address = request.client.host if request.client else None

    updated_user = await user_service.update_role(
        actor=_admin,
        clerk_id=clerk_id,
        new_role=body.role,
        request_id=request_id,
        ip_address=ip_address,
    )

    user_response = AuthenticatedUser(
        id=str(updated_user.id),
        clerk_id=updated_user.clerk_id,
        email=updated_user.email,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        image_url=updated_user.image_url,
        role=updated_user.role,
        is_active=updated_user.is_active,
        is_authenticated=True,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
    )
    return ApiResponse(
        data=user_response,
        message=f"User role updated to '{body.role.value}' successfully",
    )


@router.put(
    "/users/{clerk_id}/status",
    response_model=ApiResponse[AuthenticatedUser],
    status_code=status.HTTP_200_OK,
    summary="Update User Active Status",
    description="Activate or deactivate a user account. Requires admin role.",
    operation_id="update_user_status",
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ApiErrorResponse,
            "description": "Invalid status request",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ApiErrorResponse,
            "description": "Missing or invalid authorization token",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ApiErrorResponse,
            "description": "Admin privileges required or account disabled",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ApiErrorResponse,
            "description": "Target user not found",
        },
        status.HTTP_409_CONFLICT: {
            "model": ApiErrorResponse,
            "description": "Cannot deactivate self or the last remaining administrator",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ApiErrorResponse,
            "description": "Malformed status value or path parameter",
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "model": ApiErrorResponse,
            "description": "Rate limit exceeded",
        },
    },
)
async def update_user_status(
    request: Request,
    body: UpdateUserStatusRequest,
    _admin: CurrentAdmin,
    clerk_id: str = Path(..., pattern=r"^user_[A-Za-z0-9]+$", description="Target Clerk User ID"),
    user_service: UserService = Depends(get_user_service),
) -> ApiResponse[AuthenticatedUser]:
    request_id = request.headers.get("x-request-id")
    ip_address = request.client.host if request.client else None

    updated_user = await user_service.update_status(
        actor=_admin,
        clerk_id=clerk_id,
        is_active=body.is_active,
        request_id=request_id,
        ip_address=ip_address,
    )

    user_response = AuthenticatedUser(
        id=str(updated_user.id),
        clerk_id=updated_user.clerk_id,
        email=updated_user.email,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        image_url=updated_user.image_url,
        role=updated_user.role,
        is_active=updated_user.is_active,
        is_authenticated=True,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
    )
    status_str = "activated" if body.is_active else "deactivated"
    return ApiResponse(
        data=user_response,
        message=f"User account {status_str} successfully",
    )

