from typing import Annotated, Optional
from fastapi import Depends, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.exceptions import UnauthorizedError
from app.core.security import verify_clerk_token
from app.schemas.auth import AuthenticatedUser
from app.schemas.common import FilterParams, PaginationParams

# Native FastAPI security scheme
security = HTTPBearer(
    auto_error=False,
    description="Clerk Bearer JWT session token",
)


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
) -> AuthenticatedUser:
    """
    FastAPI native security dependency enforcing Bearer authentication.
    """
    if not credentials or not credentials.credentials:
        raise UnauthorizedError("Missing Authorization header")

    return await verify_clerk_token(credentials.credentials)


async def get_optional_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
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
    page: Annotated[int, Query(ge=1, description="Page number (1-based)")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 10,
    limit: Annotated[Optional[int], Query(ge=1, le=100, description="Limit override")] = None,
    offset: Annotated[Optional[int], Query(ge=0, description="Offset override")] = None,
) -> PaginationParams:
    """
    Dependency to parse pagination parameters with native FastAPI Query validation.
    """
    return PaginationParams(
        page=page,
        page_size=page_size,
        limit=limit,
        offset=offset,
    )


def get_filter_params(
    search: Annotated[Optional[str], Query(description="Text search filter")] = None,
    sort_by: Annotated[Optional[str], Query(description="Field name to sort results by")] = None,
    sort_order: Annotated[str, Query(pattern="^(asc|desc)$", description="Sort direction ('asc' or 'desc')")] = "asc",
) -> FilterParams:
    """
    Dependency to parse filtering, searching, and sorting parameters.
    """
    return FilterParams(
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,  # type: ignore
    )


# Modern Annotated Type Aliases for clean endpoint signatures
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]
OptionalUser = Annotated[Optional[AuthenticatedUser], Depends(get_optional_user)]
PaginationDep = Annotated[PaginationParams, Depends(get_pagination_params)]
FilterDep = Annotated[FilterParams, Depends(get_filter_params)]
