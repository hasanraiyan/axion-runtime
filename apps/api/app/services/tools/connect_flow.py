"""
ToolPolicyService and ConnectFlowService (SRS-07 FR-25, FR-28, FR-72, FR-73, FR-83).

ConnectFlowService owns the *flow* (sessions, discovery, registration, PKCE, callback); it never stores
tokens itself (``ConnectionService`` does) and never decides tool access. Link secrets and OAuth ``state``
are random and only their SHA-256 is stored; a session is single use (atomic status transitions).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union
from urllib.parse import urlencode, urlparse

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, ForbiddenError, NotFoundError, UpstreamFailureError
from app.core.protocols.tool_repositories import (
    IConnectSessionRepository,
    IIntegrationRepository,
    IOAuthClientRepository,
    IToolPolicyRepository,
)
from app.core.tools.errors import OAuthFlowFailed
from app.core.tools.oauth import new_code_verifier, new_secret_token, sha256_hex, validated_iss
from app.core.tools.ports import AuditPort, HealthProber, OAuthFlowPort, SecretReaderPort, TokenCipherPort, supports
from app.core.tools.registry import AdapterRegistry, AuthStrategyRegistry
from app.core.tools.types import Subject, SubjectType
from app.models.connection import (
    ConnectSession,
    ConnectSessionStatus,
    CredentialKind,
    IntegrationConnection,
    IntegrationOAuthClient,
    ProjectToolPolicy,
)
from app.models.integration import CredentialMode, Integration
from app.models.tool import ApprovalPolicy
from app.models.project import ProjectAuditAction
from app.services.tools.common import ProjectLifecycle
from app.services.tools.connections import ConnectionService, credentials_from_value, subject_parts

IdLike = Union[str, PydanticObjectId, ObjectId]
MAX_STATIC_SECRET = 4096


def normalize_origin(value: str) -> str:
    """Return ``scheme://host[:port]`` for an https URL (http only for localhost); reject everything else."""
    try:
        parts = urlparse(value)
        port = parts.port
    except ValueError:
        raise BadRequestError("Invalid URL") from None
    host = (parts.hostname or "").lower()
    local = host in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise BadRequestError("Return origins must use https (http is allowed only for localhost)")
    if not host or parts.username or parts.password or "*" in value:
        raise BadRequestError("Invalid return origin")
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


# ================================================================================== policy
class ToolPolicyService:
    def __init__(
        self, lifecycle: ProjectLifecycle, policy_repo: IToolPolicyRepository, audit: AuditPort, cache: Optional[Any] = None
    ) -> None:
        self._lifecycle = lifecycle
        self._policies = policy_repo
        self._audit = audit
        self._cache = cache

    async def get(self, project_id: IdLike) -> ProjectToolPolicy:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        return await self._policies.get_or_create(project.id)

    async def update(
        self,
        project_id: IdLike,
        revision: int,
        actor_id: str,
        allowed_return_origins: Optional[List[str]] = None,
        end_user_connect_enabled: Optional[bool] = None,
        connect_link_ttl_seconds: Optional[int] = None,
        default_approval_policy: Optional[ApprovalPolicy] = None,
        invocation_content_retention_days: Optional[int] = None,
        end_user_default_rate_limit_per_minute: Optional[int] = None,
    ) -> ProjectToolPolicy:
        project = await self._lifecycle.get_active(project_id)
        await self._policies.get_or_create(project.id)
        update: Dict[str, Any] = {}
        if allowed_return_origins is not None:
            if len(allowed_return_origins) > 20:
                raise BadRequestError("At most 20 return origins are allowed")
            update["allowed_return_origins"] = sorted({normalize_origin(o) for o in allowed_return_origins})
        if end_user_connect_enabled is not None:
            update["end_user_connect_enabled"] = end_user_connect_enabled
        if connect_link_ttl_seconds is not None:
            if not 60 <= connect_link_ttl_seconds <= 3600:
                raise BadRequestError("connect_link_ttl_seconds must be between 60 and 3600")
            update["connect_link_ttl_seconds"] = connect_link_ttl_seconds
        if default_approval_policy is not None:
            if default_approval_policy == ApprovalPolicy.AUTO:
                raise BadRequestError("The project default can tighten approval (require_approval or deny) but never loosen it")
            update["default_approval_policy"] = default_approval_policy
        if invocation_content_retention_days is not None:
            if not 0 <= invocation_content_retention_days <= 365:
                raise BadRequestError("invocation_content_retention_days must be between 0 and 365")
            update["invocation_content_retention_days"] = invocation_content_retention_days
        if end_user_default_rate_limit_per_minute is not None:
            if end_user_default_rate_limit_per_minute < 1:
                raise BadRequestError("end_user_default_rate_limit_per_minute must be at least 1")
            update["end_user_default_rate_limit_per_minute"] = end_user_default_rate_limit_per_minute
        updated = await self._policies.update_with_revision(project.id, revision, update)
        if self._cache is not None:
            self._cache.invalidate(project.id)
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.TOOL_POLICY_UPDATED.value, {"fields": sorted(update)}
        )
        return updated

    @staticmethod
    def check_return_url(policy: ProjectToolPolicy, return_url: Optional[str]) -> Optional[str]:
        """Exact-origin allow-list: no wildcards and no open redirects."""
        if return_url is None:
            return None
        origin = normalize_origin(return_url)
        if origin not in policy.allowed_return_origins:
            err = BadRequestError("The return URL's origin is not allowed for this project")
            err.code = "RETURN_URL_NOT_ALLOWED"
            raise err
        return return_url


# =================================================================================== flow
@dataclass
class ConnectOutcome:
    success: bool
    integration_slug: Optional[str] = None
    return_url: Optional[str] = None
    error: Optional[str] = None

    def redirect_target(self) -> Optional[str]:
        """Return URL with an outcome only: never tokens, codes, or provider error text."""
        if not self.return_url:
            return None
        query = {"status": "success" if self.success else "error"}
        if self.integration_slug:
            query["integration"] = self.integration_slug
        if self.error:
            query["error"] = self.error
        separator = "&" if "?" in self.return_url else "?"
        return self.return_url + separator + urlencode(query)


PostConnect = Callable[[str, str, str], Awaitable[Any]]


class ConnectFlowService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        adapters: AdapterRegistry,
        auth_registry: AuthStrategyRegistry,
        client_repo: IOAuthClientRepository,
        session_repo: IConnectSessionRepository,
        policy: ToolPolicyService,
        connections: ConnectionService,
        oauth: OAuthFlowPort,
        cipher: TokenCipherPort,
        secrets: SecretReaderPort,
        audit: AuditPort,
        public_base_url: str,
        post_connect: Optional[PostConnect] = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._adapters = adapters
        self._auth = auth_registry
        self._clients = client_repo
        self._sessions = session_repo
        self._policy = policy
        self._connections = connections
        self._oauth = oauth
        self._cipher = cipher
        self._secrets = secrets
        self._audit = audit
        self._base = public_base_url.rstrip("/")
        self._post_connect = post_connect

    @property
    def redirect_uri(self) -> str:
        return f"{self._base}/api/v1/integrations/oauth/callback"

    # ---------------------------------------------------------------- validation
    async def _integration(self, project_id: IdLike, integration_id: IdLike) -> Integration:
        integration = await self._integrations.get_by_id_and_project(integration_id, project_id)
        if integration is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        return integration

    def _check_subject(self, integration: Integration, subject: Subject, policy: ProjectToolPolicy) -> None:
        per_user = integration.auth_profile.credential_mode == CredentialMode.PER_USER
        if per_user and subject.type == SubjectType.PROJECT:
            raise BadRequestError("This integration needs each user to connect their own account")
        if not per_user and subject.type != SubjectType.PROJECT:
            raise BadRequestError("This integration uses the project's shared connection; only an admin connects it")
        if subject.type == SubjectType.END_USER and not policy.end_user_connect_enabled:
            err = ForbiddenError("End-user connections are not enabled for this project")
            err.code = "END_USER_CONNECT_DISABLED"
            raise err

    def _require_oauth(self, integration: Integration) -> None:
        if not self._auth.get(integration.auth_profile.auth_type).uses_connection:
            raise BadRequestError("This integration does not use an OAuth connection")

    # ------------------------------------------------------------ OAuth client
    async def _ensure_client(self, integration: Integration) -> IntegrationOAuthClient:
        adapter = self._adapters.for_integration(integration)
        urls = adapter.target_urls(integration.config)
        if not urls:
            raise BadRequestError("This integration has no remote endpoint to authorize against")
        resource_url, allowed = urls[0], adapter.allowed_hosts(integration.config)
        manual_id = (integration.auth_profile.oauth or {}).get("client_id")

        existing = await self._clients.get_by_integration(integration.id)
        if (
            existing is not None
            and existing.redirect_uri == self.redirect_uri
            and urlparse(existing.resource).netloc == urlparse(resource_url).netloc
            and (manual_id is None or existing.client_id == manual_id)
        ):
            return existing

        project_id, iid = str(integration.project_id), str(integration.id)
        try:
            discovered = await self._oauth.discover(resource_url, allowed)
            secret: Optional[str] = None
            if manual_id:
                if integration.auth_profile.secret_id:
                    secret = await self._secrets.read(project_id, str(integration.auth_profile.secret_id))
                methods = discovered.token_endpoint_auth_methods
                method = "none" if secret is None else ("client_secret_basic" if "client_secret_basic" in methods or not methods else "client_secret_post")
                client_id, dynamic = manual_id, False
            else:
                registered = await self._oauth.register_client(discovered, self.redirect_uri, "Axion")
                client_id, secret, method, dynamic = registered.client_id, registered.client_secret, registered.token_endpoint_auth_method, True
        except OAuthFlowFailed as exc:
            raise UpstreamFailureError(str(exc), code="OAUTH_SETUP_FAILED") from exc

        sealed = await self._cipher.seal(project_id, iid, "client", "oauth_client_secret", secret) if secret else None
        return await self._clients.save(
            IntegrationOAuthClient(
                project_id=integration.project_id,
                integration_id=integration.id,
                issuer=discovered.issuer,
                resource=discovered.resource,
                authorization_endpoint=discovered.authorization_endpoint,
                token_endpoint=discovered.token_endpoint,
                revocation_endpoint=discovered.revocation_endpoint,
                client_id=client_id,
                client_secret_envelope=sealed,
                token_endpoint_auth_method=method,
                redirect_uri=self.redirect_uri,
                dynamically_registered=dynamic,
                scopes=list((integration.auth_profile.oauth or {}).get("scopes", [])),
                iss_required=discovered.iss_response_supported,
            )
        )

    # -------------------------------------------------------------- link/session
    async def _new_session(
        self, project_id: Any, integration: Integration, subject: Subject, return_url: Optional[str], actor_id: str, ttl: int
    ) -> tuple[ConnectSession, str]:
        stype, sid, skey = subject_parts(subject)
        token = new_secret_token()
        session = await self._sessions.create(
            ConnectSession(
                token_hash=sha256_hex(token),
                project_id=project_id,
                integration_id=integration.id,
                subject_type=stype,
                subject_id=sid,
                subject_key=skey,
                created_by=actor_id,
                return_url=return_url,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
            )
        )
        return session, token

    async def create_link(
        self, project_id: IdLike, integration_id: IdLike, subject: Subject, return_url: Optional[str], actor_id: str
    ) -> tuple[str, int]:
        """A single-use hosted link that starts the flow for exactly one subject (FR-72)."""
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integration(project.id, integration_id)
        self._require_oauth(integration)
        policy = await self._policy.get(project.id)
        self._check_subject(integration, subject, policy)
        validated = self._policy.check_return_url(policy, return_url)
        _, token = await self._new_session(project.id, integration, subject, validated, actor_id, policy.connect_link_ttl_seconds)
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.CONNECT_LINK_CREATED.value,
            {"integration_id": str(integration.id), "subject": subject.key},
        )
        return f"{self._base}/api/v1/integrations/connect/{token}", policy.connect_link_ttl_seconds

    async def start_authorization(
        self, project_id: IdLike, integration_id: IdLike, subject: Subject, return_url: Optional[str], actor_id: str
    ) -> str:
        """Create a session and return the provider authorization URL immediately (admin/member flows)."""
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integration(project.id, integration_id)
        self._require_oauth(integration)
        policy = await self._policy.get(project.id)
        self._check_subject(integration, subject, policy)
        validated = self._policy.check_return_url(policy, return_url)
        _, token = await self._new_session(project.id, integration, subject, validated, actor_id, policy.connect_link_ttl_seconds)
        return await self.begin(token)

    async def begin(self, token: str) -> str:
        """Open a link: discover/register, create PKCE and state, and return the authorization URL."""
        session = await self._sessions.get_by_token_hash(sha256_hex(token))
        if session is None or session.status != ConnectSessionStatus.PENDING or _expired(session):
            raise _session_error()
        integration = await self._integration(session.project_id, session.integration_id)
        client = await self._ensure_client(integration)

        verifier, state = new_code_verifier(), new_secret_token()
        sealed = await self._cipher.seal(str(session.project_id), str(integration.id), session.subject_key, "pkce", verifier)
        started = await self._sessions.mark_started(session.id, sha256_hex(state), sealed)
        if started is None:
            raise _session_error()
        return self._oauth.authorization_url(
            client.authorization_endpoint,
            client.client_id,
            client.redirect_uri,
            state,
            verifier,
            list((integration.auth_profile.oauth or {}).get("scopes", [])),
            client.resource,
        )

    # ----------------------------------------------------------------- callback
    async def complete(
        self, state: Optional[str], code: Optional[str], error: Optional[str] = None, iss: Optional[str] = None
    ) -> ConnectOutcome:
        if not state:
            return ConnectOutcome(False, error="invalid_request")
        session = await self._sessions.get_by_state_hash(sha256_hex(state))
        if session is None:
            return ConnectOutcome(False, error="unknown_state")
        return_url = session.return_url
        if session.status != ConnectSessionStatus.STARTED or _expired(session):
            return ConnectOutcome(False, return_url=return_url, error="connect_session_expired")

        # Claim the session atomically: a replayed callback finds it already consumed.
        claimed = await self._sessions.finish(session.id, ConnectSessionStatus.COMPLETED)
        if claimed is None:
            return ConnectOutcome(False, return_url=return_url, error="connect_session_expired")

        integration = await self._integrations.get_by_id_and_project(session.integration_id, session.project_id)
        client = await self._clients.get_by_integration(session.integration_id)
        if integration is None or client is None or session.pkce_verifier_envelope is None:
            await self._sessions.mark_failed(session.id, "integration_unavailable")
            return ConnectOutcome(False, return_url=return_url, error="integration_unavailable")
        slug = integration.slug

        if error or not code:
            await self._sessions.mark_failed(session.id, "provider_denied")
            return ConnectOutcome(False, slug, return_url, "access_denied")
        try:
            validated_iss(iss, client.issuer, client.iss_required)
            project_id, iid = str(session.project_id), str(session.integration_id)
            verifier = await self._cipher.open(project_id, iid, session.subject_key, "pkce", session.pkce_verifier_envelope)
            secret = (
                await self._cipher.open(project_id, iid, "client", "oauth_client_secret", client.client_secret_envelope)
                if client.client_secret_envelope
                else None
            )
            tokens = await self._oauth.exchange_code(
                client.token_endpoint, code, client.redirect_uri, verifier, client.client_id, secret,
                client.token_endpoint_auth_method, client.resource,
            )
            subject = Subject(SubjectType(session.subject_type.value), id=session.subject_id)
            await self._connections.store_oauth(project_id, integration, subject, tokens)
        except OAuthFlowFailed:
            await self._sessions.mark_failed(session.id, "token_exchange_failed")
            return ConnectOutcome(False, slug, return_url, "token_exchange_failed")

        if session.subject_type.value == "project" and self._post_connect is not None:
            try:
                await self._post_connect(str(session.project_id), str(session.integration_id), session.created_by)
            except Exception:  # verification is best-effort; the connection itself is stored
                pass
        return ConnectOutcome(True, slug, return_url)

    # --------------------------------------------------------------- key entry
    async def connect_static(
        self, project_id: IdLike, integration_id: IdLike, subject: Subject, value: str, actor_id: str
    ) -> IntegrationConnection:
        """Store a user-supplied API key or bearer token after verifying it against the integration (FR-28)."""
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integration(project.id, integration_id)
        strategy = self._auth.get(integration.auth_profile.auth_type)
        kind_name = getattr(strategy, "static_kind", None)
        if kind_name is None or integration.auth_profile.credential_mode != CredentialMode.PER_USER:
            raise BadRequestError("This integration does not accept a user-supplied key")
        policy = await self._policy.get(project.id)
        self._check_subject(integration, subject, policy)
        if not value or len(value) > MAX_STATIC_SECRET or any(c in value for c in "\r\n\x00"):
            raise BadRequestError("Invalid credential value")

        kind = CredentialKind(kind_name)
        adapter = self._adapters.for_integration(integration)
        if supports(adapter, HealthProber):
            probe = await adapter.probe(integration, credentials_from_value(integration.auth_profile, kind, value))
            if not probe.healthy:
                err = BadRequestError(
                    "The service rejected these credentials" if probe.status == "auth_failed" else "The service could not be reached to verify these credentials"
                )
                err.code = "CREDENTIALS_REJECTED" if probe.status == "auth_failed" else "CREDENTIALS_UNVERIFIED"
                raise err
        return await self._connections.store_static(str(project.id), integration, subject, kind, value)


def _expired(session: ConnectSession) -> bool:
    expires = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)


def _session_error() -> BadRequestError:
    err = BadRequestError("This connect link is invalid, expired, or already used")
    err.code = "CONNECT_SESSION_EXPIRED"
    return err
