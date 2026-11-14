from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import ApiResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get(
    "/me",
    response_model=ApiResponse[AuthenticatedUser],
    summary="Get Authenticated User",
    description="Retrieve the current verified Clerk user profile and session identity.",
    operation_id="get_current_authenticated_user",
)
async def get_me(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> ApiResponse[AuthenticatedUser]:
    return ApiResponse(
        data=current_user,
        message="Authenticated user profile retrieved successfully",
    )
