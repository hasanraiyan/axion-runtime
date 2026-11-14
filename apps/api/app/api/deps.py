from typing import Optional
from fastapi import Depends, Header, Query
from app.core.exceptions import UnauthorizedError
from app.core.security import verify_clerk_token
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import FilterParams, PaginationParams


async def get_current_user(
    authorization: Optional[str] = Header(None, description="Bearer token issued by Clerk"),
) -> AuthenticatedUser:
    """
    FastAPI dependency that enforces authentication and returns the current verified Clerk user.
    """
    if not authorization:
        raise UnauthorizedError("Missing Authorization header")

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Invalid Authorization format. Expected: 'Bearer <token>'")

    token = parts[1]
    return await verify_clerk_token(token)


async def get_optional_user(
    authorization: Optional[str] = Header(None, description="Optional Bearer token issued by Clerk"),
) -> Optional[AuthenticatedUser]:
    """
    FastAPI dependency for endpoints that allow both guest and authenticated user access.
    """
    if not authorization:
        return None

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    try:
        return await verify_clerk_token(parts[1])
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
