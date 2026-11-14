from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import time
from typing import Annotated, Dict, List, Optional, Union
from fastapi import Depends, Header, Query, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.core.exceptions import (
    CredentialExpiredError,
    CredentialRevokedError,
    ForbiddenError,
    InsufficientScopeError,
    InvalidCredentialError,
    NotFoundError,
    ProjectAccessDeniedError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
    RateLimitExceededError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from app.core.logging import logger
from app.core.security import verify_clerk_token
from app.db.client import get_global_client, get_global_database
from app.models.credential import CredentialStatus
from app.models.project import ProjectMember, ProjectRole, ProjectStatus
from app.models.user import UserRole
from app.repositories.credential_repository import (
    ProjectCredentialRepository,
    get_credential_repository,
)
from app.repositories.project_member_repository import (
    ProjectMemberRepository,
    get_project_member_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.schemas.auth import AuthenticatedActor, AuthenticatedUser
from app.schemas.common import FilterParams, PaginationParams
from app.services.credential_service import (
    ProjectCredentialService,
    get_credential_service,
)
from app.services.project_audit_service import (
    ProjectAuditService,
    get_project_audit_service,
)
from app.services.project_member_service import (
    ProjectMemberService,
    get_project_member_service,
)
from app.services.project_service import (
    ProjectService,
    get_project_service,
)
from app.services.runtime_secret_resolver import (
    RuntimeSecretResolver,
    get_runtime_secret_resolver,
)
from app.services.secret_service import (
    ProjectSecretService,
    get_secret_service,
)
from app.services.user_service import UserService, get_user_service

# Native FastAPI security scheme
security = HTTPBearer(
    auto_error=False,
    description="Clerk Bearer JWT session token",
)

api_key_header_scheme = APIKeyHeader(
    name="X-Axion-Api-Key",
    auto_error=False,
    description="Axion Project API Key (e.g. axion_live_...)",
)

_credential_rate_records: Dict[str, List[float]] = defaultdict(list)


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> AuthenticatedUser:
    """
    FastAPI native security dependency enforcing Bearer authentication.
    Verifies Clerk token and synchronizes user identity into MongoDB.
    """
    if not credentials or not credentials.credentials:
        raise UnauthorizedError("Missing Authorization header")

    clerk_user = await verify_clerk_token(credentials.credentials)

    try:
        db_user = await user_service.sync_clerk_user(
            clerk_id=clerk_user.clerk_id,
            email=clerk_user.email,
            first_name=clerk_user.first_name,
            last_name=clerk_user.last_name,
            image_url=clerk_user.image_url,
        )
        if db_user is not None:
            return AuthenticatedUser(
                id=str(db_user.id),
                clerk_id=db_user.clerk_id,
                email=db_user.email,
                first_name=db_user.first_name,
                last_name=db_user.last_name,
                image_url=db_user.image_url,
                role=db_user.role,
                roles=[db_user.role.value],
                is_active=db_user.is_active,
                is_authenticated=True,
                created_at=db_user.created_at,
                updated_at=db_user.updated_at,
            )
    except Exception as exc:
        logger.debug(f"User DB sync bypassed (DB offline or uninitialized): {exc}")

    return clerk_user


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


def get_mongo_client(request: Request) -> AsyncMongoClient:
    """
    Dependency to retrieve the active MongoDB AsyncMongoClient.
    """
    client = getattr(request.app.state, "mongo_client", None) or get_global_client()
    if client is None:
        raise ServiceUnavailableError("MongoDB client is not initialized or unavailable")
    return client


def get_database(request: Request) -> AsyncDatabase:
    """
    Dependency to retrieve the active MongoDB AsyncDatabase.
    """
    db = getattr(request.app.state, "mongo_db", None) or get_global_database()
    if db is None:
        raise ServiceUnavailableError("MongoDB database is not initialized or unavailable")
    return db


def require_role(required_role: UserRole):
    """
    Factory dependency enforcing role-based access control (RBAC).
    """

    async def role_checker(
        current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    ) -> AuthenticatedUser:
        if current_user.role != required_role:
            raise ForbiddenError(
                f"Insufficient permissions: requires '{required_role.value}' role"
            )
        return current_user

    return role_checker


def require_project_role(*allowed_roles: ProjectRole):
    """
    FastAPI dependency factory enforcing project-level Role-Based Access Control (RBAC).
    Extracts project_id or slug from path/query parameter.
    Verifies caller's membership via ProjectMemberRepository / ProjectRepository.
    If caller is not a member (and not super admin), raises NotFoundError("Project not found")
    to eliminate tenant resource enumeration vulnerabilities per SRS Section 8.3.
    If caller is a member but lacks sufficient role, raises ForbiddenError.
    Attaches current project, caller role, and member to request.state and returns ProjectMember.
    """
    ROLE_HIERARCHY = {
        ProjectRole.VIEWER: 1,
        ProjectRole.MEMBER: 2,
        ProjectRole.ADMIN: 3,
        ProjectRole.OWNER: 4,
    }

    async def project_role_checker(
        request: Request,
        current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
        project_repo: Annotated[ProjectRepository, Depends(get_project_repository)],
        member_repo: Annotated[ProjectMemberRepository, Depends(get_project_member_repository)],
    ) -> ProjectMember:
        identifier = (
            request.path_params.get("project_id")
            or request.query_params.get("project_id")
            or request.path_params.get("slug")
            or request.query_params.get("slug")
        )
        if not identifier:
            raise NotFoundError("Project not found")

        project = await project_repo.get_by_id_or_slug(identifier)
        if project is None:
            raise NotFoundError("Project not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))

        is_super_admin = (current_user.role == UserRole.ADMIN)

        member = await member_repo.get_membership(project.id, current_user.clerk_id)
        if member is None and not is_super_admin:
            raise NotFoundError("Project not found")

        # In SOFT_DELETED state: project access restricted to OWNER only (unless super admin)
        if project.status == ProjectStatus.SOFT_DELETED and not is_super_admin:
            if member is None or member.role != ProjectRole.OWNER:
                raise NotFoundError("Project not found")

        caller_role = (
            member.role
            if member is not None
            else (
                ProjectRole.OWNER
                if (is_super_admin and project.owner_id == current_user.clerk_id)
                else (ProjectRole.ADMIN if is_super_admin else None)
            )
        )

        if allowed_roles and not is_super_admin:
            if caller_role is None:
                raise ForbiddenError("Insufficient project permissions")
            min_required = min(ROLE_HIERARCHY.get(r, 0) for r in allowed_roles)
            caller_level = ROLE_HIERARCHY.get(caller_role, 0)
            if caller_role not in allowed_roles and caller_level < min_required:
                raise ForbiddenError("Insufficient project permissions")

        effective_member = member or ProjectMember(
            project_id=project.id,
            user_id=current_user.clerk_id,
            role=caller_role or ProjectRole.ADMIN,
        )

        request.state.project = project
        request.state.project_role = caller_role
        request.state.project_member = effective_member

        return effective_member

    return project_role_checker


class ApiKeyAuth:
    """
    FastAPI security dependency for machine API key authentication.
    Validates X-Axion-Api-Key or Authorization: Bearer axion_...
    Enforces project tenant isolation boundary, capability scopes, and per-key rate limits.
    Injects AuthenticatedActor and Project into request.state.
    Supports usage as:
    - Depends(get_api_key_auth(["projects:read"]))
    - Depends(get_api_key_auth())
    - Depends(get_api_key_auth)
    - await get_api_key_auth(request, ...)
    """

    def __init__(
        self,
        required_scopes: Optional[Union[List[str], str, Request]] = None,
        *args,
        **kwargs,
    ) -> None:
        if isinstance(required_scopes, Request):
            self._is_direct_call = True
            self.required_scopes = []
            self._coro = self._execute(required_scopes, *args, **kwargs)
        else:
            self._is_direct_call = False
            if isinstance(required_scopes, str):
                self.required_scopes = [required_scopes]
            elif required_scopes is not None:
                self.required_scopes = list(required_scopes)
            else:
                self.required_scopes = []

    def __await__(self):
        if getattr(self, "_is_direct_call", False):
            return self._coro.__await__()
        raise TypeError("ApiKeyAuth instance is only awaitable when invoked directly with Request")

    async def _execute(
        self,
        request: Request,
        header_key: Optional[str] = None,
        authorization: Optional[str] = None,
        cred_repo: Optional[ProjectCredentialRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
    ) -> AuthenticatedActor:
        if header_key is None and "x-axion-api-key" in request.headers:
            header_key = request.headers.get("x-axion-api-key")
        if authorization is None and "authorization" in request.headers:
            authorization = request.headers.get("authorization")

        # 1. Extract raw key from X-Axion-Api-Key or Authorization Bearer
        raw_key = header_key
        if not raw_key and authorization:
            parts = authorization.strip().split()
            if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].startswith("axion_"):
                raw_key = parts[1]

        if not raw_key:
            raise UnauthorizedError("Missing API key. Provide X-Axion-Api-Key or Authorization: Bearer axion_...")

        raw_key = raw_key.strip()

        # 2. Format pre-validation
        if not (raw_key.startswith("axion_live_") or raw_key.startswith("axion_test_")):
            raise InvalidCredentialError("Invalid API key format. Key must start with 'axion_live_' or 'axion_test_'")

        # 3. Hash raw key
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        # 4. Lookup credential in MongoDB
        if cred_repo is None:
            cred_repo = get_credential_repository()
        credential = await cred_repo.get_by_hash(key_hash)
        if credential is None or credential.is_deleted:
            raise InvalidCredentialError("Invalid API key")

        # 5. Validate status and expiration
        if credential.status == CredentialStatus.REVOKED:
            raise CredentialRevokedError()

        now = datetime.now(timezone.utc)
        if credential.expires_at is not None:
            exp = credential.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                raise CredentialExpiredError()

        # 6. Verify parent project state
        if project_repo is None:
            project_repo = get_project_repository()
        project = await project_repo.get_by_id(credential.project_id)
        if project is None or project.status == ProjectStatus.PURGED:
            raise NotFoundError("Project not found")
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))

        # 7. Strict Project Isolation Boundary Check
        route_project_identifier = (
            request.path_params.get("project_id")
            or request.path_params.get("slug")
            or request.query_params.get("project_id")
            or request.query_params.get("slug")
        )
        if route_project_identifier:
            if str(route_project_identifier) not in (str(project.id), project.slug):
                raise ProjectAccessDeniedError()

        # 8. Project Archived State Check (Read-only allowed; mutations blocked)
        if project.status == ProjectStatus.ARCHIVED and request.method not in ("GET", "HEAD", "OPTIONS"):
            raise ProjectArchivedError(str(project.id))

        # 9. Check per-credential rate limit
        if credential.rate_limit_rpm:
            cred_id_str = str(credential.id)
            current_time = time.time()
            window_start = current_time - 60.0
            timestamps = [ts for ts in _credential_rate_records[cred_id_str] if ts > window_start]
            _credential_rate_records[cred_id_str] = timestamps

            if len(timestamps) >= credential.rate_limit_rpm:
                raise RateLimitExceededError(
                    f"Rate limit of {credential.rate_limit_rpm} requests per minute exceeded for this credential."
                )
            _credential_rate_records[cred_id_str].append(current_time)

        # 10. Validate scopes
        granted = set(credential.scopes)
        if "*" not in granted:
            for req in self.required_scopes:
                if req not in granted:
                    raise InsufficientScopeError(req)

        # 11. Create unified AuthenticatedActor
        actor = AuthenticatedActor(
            actor_type="credential",
            identity_id=str(credential.id),
            project_id=str(project.id),
            scopes=credential.scopes,
            email=None,
            is_authenticated=True,
        )

        # 12. Attach to request.state for downstream handlers
        request.state.actor = actor
        request.state.project = project
        request.state.credential = credential
        request.state.auth_type = "api_key"

        # 13. Trigger debounced last_used update (with non-dropping total_uses)
        try:
            await cred_repo.record_usage_debounced(
                credential_id=credential.id,
                client_ip=request.client.host if request.client else None,
                current_last_used=credential.last_used_at,
            )
        except Exception as exc:
            logger.debug(f"Credential usage debounced telemetry write failed: {exc}")

        return actor

    async def __call__(
        self,
        request: Request,
        header_key: Annotated[Optional[str], Security(api_key_header_scheme)] = None,
        authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
        cred_repo: Annotated[ProjectCredentialRepository, Depends(get_credential_repository)] = None,
        project_repo: Annotated[ProjectRepository, Depends(get_project_repository)] = None,
    ) -> AuthenticatedActor:
        return await self._execute(
            request=request,
            header_key=header_key,
            authorization=authorization,
            cred_repo=cred_repo,
            project_repo=project_repo,
        )


get_api_key_auth = ApiKeyAuth


def require_api_key_scopes(*required_scopes: str) -> ApiKeyAuth:
    """Convenience factory for API key scope checking."""
    return ApiKeyAuth(list(required_scopes))


class AuthenticatedContextAuth:
    """
    Dual-mode authentication dependency supporting both human Clerk sessions
    and machine API keys. Establishes unified AuthenticatedActor and Project on request.state.
    Supports usage as:
    - Depends(get_authenticated_context(["projects:read"]))
    - Depends(get_authenticated_context())
    - Depends(get_authenticated_context)
    - await get_authenticated_context(request, ...)
    """

    def __init__(
        self,
        required_scopes: Optional[Union[List[str], str, Request]] = None,
        *args,
        **kwargs,
    ) -> None:
        if isinstance(required_scopes, Request):
            self._is_direct_call = True
            self.required_scopes = []
            self._coro = self._execute(required_scopes, *args, **kwargs)
        else:
            self._is_direct_call = False
            if isinstance(required_scopes, str):
                self.required_scopes = [required_scopes]
            elif required_scopes is not None:
                self.required_scopes = list(required_scopes)
            else:
                self.required_scopes = []
        self._api_key_auth = ApiKeyAuth(self.required_scopes)

    def __await__(self):
        if getattr(self, "_is_direct_call", False):
            return self._coro.__await__()
        raise TypeError("AuthenticatedContextAuth instance is only awaitable when invoked directly with Request")

    async def _execute(
        self,
        request: Request,
        header_key: Optional[str] = None,
        authorization: Optional[str] = None,
        cred_repo: Optional[ProjectCredentialRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
        member_repo: Optional[ProjectMemberRepository] = None,
    ) -> AuthenticatedActor:
        if header_key is None and "x-axion-api-key" in request.headers:
            header_key = request.headers.get("x-axion-api-key")
        if authorization is None and "authorization" in request.headers:
            authorization = request.headers.get("authorization")

        # 1. Determine if caller is presenting machine API key
        is_api_key = bool(header_key)
        if not is_api_key and authorization:
            parts = authorization.strip().split()
            if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].startswith("axion_"):
                is_api_key = True

        if is_api_key:
            return await self._api_key_auth._execute(
                request=request,
                header_key=header_key,
                authorization=authorization,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

        # 2. Otherwise verify human Clerk user
        if not authorization:
            raise UnauthorizedError(
                "Missing authentication credentials. Provide X-Axion-Api-Key or Authorization: Bearer <token>"
            )

        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise UnauthorizedError("Invalid Authorization header format. Expected 'Bearer <token>'.")

        clerk_token = parts[1]
        clerk_user = await verify_clerk_token(clerk_token)

        if project_repo is None:
            project_repo = get_project_repository()
        if member_repo is None:
            member_repo = get_project_member_repository()

        identifier = (
            request.path_params.get("project_id")
            or request.path_params.get("slug")
            or request.query_params.get("project_id")
            or request.query_params.get("slug")
        )

        project = None
        if identifier:
            project = await project_repo.get_by_id_or_slug(identifier)
            if project is None:
                raise NotFoundError("Project not found")
            if project.status == ProjectStatus.PURGED:
                raise ProjectPurgedError(str(project.id))
            if project.status == ProjectStatus.SOFT_DELETED:
                raise ProjectDeletedError(str(project.id))

            is_super_admin = (clerk_user.role == UserRole.ADMIN)
            member = await member_repo.get_membership(project.id, clerk_user.clerk_id)
            if member is None and not is_super_admin:
                raise NotFoundError("Project not found")

            caller_role = (
                member.role
                if member is not None
                else (
                    ProjectRole.OWNER
                    if (is_super_admin and project.owner_id == clerk_user.clerk_id)
                    else (ProjectRole.ADMIN if is_super_admin else None)
                )
            )
            request.state.project = project
            request.state.project_role = caller_role
            request.state.project_member = member

        actor = AuthenticatedActor(
            actor_type="user",
            identity_id=clerk_user.clerk_id,
            project_id=str(project.id) if project else None,
            scopes=["*"],
            email=clerk_user.email,
            is_authenticated=True,
        )
        request.state.actor = actor
        request.state.auth_type = "clerk"
        return actor

    async def __call__(
        self,
        request: Request,
        header_key: Annotated[Optional[str], Security(api_key_header_scheme)] = None,
        authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
        cred_repo: Annotated[ProjectCredentialRepository, Depends(get_credential_repository)] = None,
        project_repo: Annotated[ProjectRepository, Depends(get_project_repository)] = None,
        member_repo: Annotated[ProjectMemberRepository, Depends(get_project_member_repository)] = None,
    ) -> AuthenticatedActor:
        return await self._execute(
            request=request,
            header_key=header_key,
            authorization=authorization,
            cred_repo=cred_repo,
            project_repo=project_repo,
            member_repo=member_repo,
        )


get_authenticated_context = AuthenticatedContextAuth


# Modern Annotated Type Aliases for clean endpoint signatures
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]
OptionalUser = Annotated[Optional[AuthenticatedUser], Depends(get_optional_user)]
CurrentAdmin = Annotated[AuthenticatedUser, Depends(require_role(UserRole.ADMIN))]
PaginationDep = Annotated[PaginationParams, Depends(get_pagination_params)]
FilterDep = Annotated[FilterParams, Depends(get_filter_params)]
MongoClientDep = Annotated[AsyncMongoClient, Depends(get_mongo_client)]
DatabaseDep = Annotated[AsyncDatabase, Depends(get_database)]
ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]
ProjectMemberServiceDep = Annotated[ProjectMemberService, Depends(get_project_member_service)]
ProjectAuditServiceDep = Annotated[ProjectAuditService, Depends(get_project_audit_service)]
SecretServiceDep = Annotated[ProjectSecretService, Depends(get_secret_service)]
SecretResolverDep = Annotated[RuntimeSecretResolver, Depends(get_runtime_secret_resolver)]
CredentialServiceDep = Annotated[ProjectCredentialService, Depends(get_credential_service)]
CredentialRepoDep = Annotated[ProjectCredentialRepository, Depends(get_credential_repository)]
ApiKeyAuthDep = Annotated[AuthenticatedActor, Depends(get_api_key_auth)]
AuthenticatedContextDep = Annotated[AuthenticatedActor, Depends(get_authenticated_context)]
