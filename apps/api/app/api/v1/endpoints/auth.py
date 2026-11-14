from fastapi import APIRouter, status
from app.api.deps import CurrentUser
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import ApiErrorResponse, ApiResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get(
    "/me",
    response_model=ApiResponse[AuthenticatedUser],
    status_code=status.HTTP_200_OK,
    summary="Get Authenticated User",
    description="Retrieve the current verified Clerk user profile and session identity.",
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
