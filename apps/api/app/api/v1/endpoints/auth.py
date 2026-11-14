from fastapi import APIRouter, Path, status
from app.api.deps import CurrentAdmin, CurrentUser
from app.core.exceptions import NotFoundError
from app.schemas.auth import AuthenticatedUser, UpdateUserRoleRequest
from app.schemas.common import ApiErrorResponse, ApiResponse
from app.services.user_service import UserService

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
    },
)
async def get_me(current_user: CurrentUser) -> ApiResponse[AuthenticatedUser]:
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
        status.HTTP_401_UNAUTHORIZED: {
            "model": ApiErrorResponse,
            "description": "Missing or invalid authorization token",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ApiErrorResponse,
            "description": "Admin privileges required",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ApiErrorResponse,
            "description": "Target user not found",
        },
    },
)
async def update_user_role(
    body: UpdateUserRoleRequest,
    clerk_id: str = Path(..., description="Target Clerk User ID"),
    _admin: CurrentAdmin = None,  # type: ignore[assignment]
) -> ApiResponse[AuthenticatedUser]:
    updated_user = await UserService.update_role(clerk_id, body.role)
    if not updated_user:
        raise NotFoundError(f"User with Clerk ID '{clerk_id}' not found")

    user_response = AuthenticatedUser(
        id=str(updated_user.id),
        clerk_id=updated_user.clerk_id,
        email=updated_user.email,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        image_url=updated_user.image_url,
        role=updated_user.role,
        roles=[updated_user.role.value],
        is_active=updated_user.is_active,
        is_authenticated=True,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
    )
    return ApiResponse(
        data=user_response,
        message=f"User role updated to '{body.role.value}' successfully",
    )
