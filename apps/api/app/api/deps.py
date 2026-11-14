from typing import Optional
from fastapi import Depends, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.exceptions import UnauthorizedError
from app.core.security import verify_clerk_token
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import FilterParams, PaginationParams

# Native FastAPI security scheme
security = HTTPBearer(
    auto_error=False,
    description="Clerk Bearer JWT token",
)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """
    FastAPI security dependency that enforces Bearer token authentication and returns verified Clerk user.
    """
    if not credentials or not credentials.credentials:
        raise UnauthorizedError("Missing Authorization header")

    return await verify_clerk_token(credentials.credentials)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[AuthenticatedUser]:
    """
    FastAPI security dependency for endpoints that allow both guest and authenticated user access.
    """
    if not credentials or not credentials.credentials:
        return None

    try:
        return await verify_clerk_token(credentials.credentials)
    except Exception:
        return None


def get_pagination_params(
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=10, ge=1, le=100, description="Items per page"),
    limit: Optional[int] = Query(default=None, ge=1, le=100, description="Limit override"),
    offset: Optional[int] = Query(default=None, ge=0, description="Offset override"),
) -> PaginationParams:
    """
    Dependency to parse pagination parameters.
    """
    return PaginationParams(
        page=page,
        page_size=page_size,
        limit=limit,
        offset=offset,
    )


def get_filter_params(
    search: Optional[str] = Query(default=None, description="Text search filter"),
    sort_by: Optional[str] = Query(default=None, description="Field name to sort results by"),
    sort_order: str = Query(default="asc", pattern="^(asc|desc)$", description="Sort direction ('asc' or 'desc')"),
) -> FilterParams:
    """
    Dependency to parse filtering, searching, and sorting parameters.
    """
    return FilterParams(
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
