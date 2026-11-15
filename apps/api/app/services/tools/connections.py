"""
Connections (SRS-07 FR-24..FR-29, FR-79): ``ConnectionService`` (records and lifecycle),
``ConnectionTokenService`` (credential resolution and token refresh), and ``TokenCipher``.

A connection belongs to exactly one subject. Credentials are sealed with AAD bound to
``(project, integration, subject)``; nothing here ever returns them to a caller other than the
Gateway's in-memory ``ResolvedCredentials``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.crypto import CryptoService
from app.core.crypto.envelope import EncryptedEnvelope
from app.core.exceptions import NotFoundError
from app.core.protocols.tool_repositories import (
    IConnectionRepository,
    IIntegrationRepository,
    IOAuthClientRepository,
)
from app.core.tools.errors import OAuthFlowFailed, OAuthInvalidClient, OAuthInvalidGrant, UpstreamError
from app.core.tools.oauth import TokenSet
from app.core.tools.ports import AuditPort, OAuthFlowPort, TokenCipherPort
from app.core.tools.resilience import KeyedLocks
from app.core.tools.types import ResolvedCredentials, Subject, SubjectType
from app.models.connection import (
    ConnectionStatus,
    ConnectionSubjectType,
    CredentialKind,
    IntegrationConnection,
    IntegrationOAuthClient,
)
from app.models.integration import AuthProfile, CredentialMode, Integration, IntegrationStatus
from app.models.project import ProjectAuditAction
from app.services.tools.common import ProjectLifecycle
from app.services.tools.credentials import AuthRequired

IdLike = Union[str, PydanticObjectId, ObjectId]
REFRESH_SKEW = timedelta(seconds=60)
LAST_USED_DEBOUNCE = timedelta(hours=1)

_SUBJECT_TYPES = {
    SubjectType.PROJECT: ConnectionSubjectType.PROJECT,
    SubjectType.MEMBER: ConnectionSubjectType.MEMBER,
    SubjectType.END_USER: ConnectionSubjectType.END_USER,
}


def subject_parts(subject: Subject) -> Tuple[ConnectionSubjectType, Optional[str], str]:
    return _SUBJECT_TYPES[subject.type], (None if subject.type == SubjectType.PROJECT else subject.id), subject.key


def credentials_from_value(profile: AuthProfile, kind: CredentialKind, value: str) -> ResolvedCredentials:
    """Build outbound credentials from one stored secret value, according to the integration's auth profile."""
    if kind == CredentialKind.API_KEY:
        rendered = f"{profile.prefix or ''}{value}"
        name = profile.name or "X-API-Key"
        if (profile.placement or "header") == "query":
            return ResolvedCredentials(query={name: rendered})
        return ResolvedCredentials(headers={name: rendered})
    return ResolvedCredentials(headers={"Authorization": f"Bearer {value}"})


class TokenCipher:
    """``TokenCipherPort`` over MOD-02 envelope encryption with subject-bound AAD."""

    def __init__(self, crypto: CryptoService) -> None:
        self._crypto = crypto

    @staticmethod
    def _binding(integration_id: str, subject_key: str, label: str) -> Tuple[str, str]:
        return f"conn:{subject_key}", f"{integration_id}:{label}"

    async def seal(self, project_id: str, integration_id: str, subject_key: str, label: str, plaintext: str) -> EncryptedEnvelope:
        environment, name = self._binding(integration_id, subject_key, label)
        return await self._crypto.encrypt_secret(plaintext, project_id, environment, name)

    async def open(self, project_id: str, integration_id: str, subject_key: str, label: str, envelope: EncryptedEnvelope) -> str:
        environment, name = self._binding(integration_id, subject_key, label)
        return await self._crypto.decrypt_secret(envelope, project_id, environment, name)


class ConnectionService:
    """Connection records and lifecycle. Also implements ``EndUserConnectionPort``."""

    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        connection_repo: IConnectionRepository,
        integration_repo: IIntegrationRepository,
        oauth_client_repo: IOAuthClientRepository,
        cipher: TokenCipherPort,
        oauth: OAuthFlowPort,
        audit: AuditPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._connections = connection_repo
        self._integrations = integration_repo
        self._clients = oauth_client_repo
        self._cipher = cipher
        self._oauth = oauth
        self._audit = audit

    # ------------------------------------------------------------------- storing
    async def store_oauth(
        self, project_id: str, integration: Integration, subject: Subject, tokens: TokenSet, label: Optional[str] = None
    ) -> IntegrationConnection:
        stype, sid, skey = subject_parts(subject)
        iid = str(integration.id)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=tokens.expires_in) if tokens.expires_in else None
        access = await self._cipher.seal(project_id, iid, skey, "access", tokens.access_token)
        refresh = await self._cipher.seal(project_id, iid, skey, "refresh", tokens.refresh_token) if tokens.refresh_token else None
        connection = await self._connections.save_credentials(
            project_id, integration.id, stype, sid, skey, CredentialKind.OAUTH, access, refresh, expires_at,
            tokens.scopes, {"label": label} if label else {},
        )
        await self._after_store(project_id, integration, subject, connection)
        return connection

    async def store_static(
        self, project_id: str, integration: Integration, subject: Subject, kind: CredentialKind, value: str
    ) -> IntegrationConnection:
        stype, sid, skey = subject_parts(subject)
        sealed = await self._cipher.seal(project_id, str(integration.id), skey, "access", value)
        connection = await self._connections.save_credentials(
            project_id, integration.id, stype, sid, skey, kind, sealed, None, None, [], {}
        )
        await self._after_store(project_id, integration, subject, connection)
        return connection

    async def _after_store(self, project_id: str, integration: Integration, subject: Subject, connection: IntegrationConnection) -> None:
        await self._audit.record(
            project_id,
            subject.id or "project",
            ProjectAuditAction.CONNECTION_CREATED.value,
            {"integration_id": str(integration.id), "subject": subject.key, "kind": connection.credential_kind.value},
        )
        # A project-wide credential that was missing or dead is repaired by reconnecting.
        if subject.type == SubjectType.PROJECT and integration.status in (IntegrationStatus.NEEDS_AUTH, IntegrationStatus.DRAFT):
            await self._integrations.update_runtime_state(
                integration.id, integration.project_id, {"status": IntegrationStatus.DRAFT, "status_reason": "Connected; verify the integration"}
            )

    # ------------------------------------------------------------------- reading
    async def list_for_integration(
        self, project_id: IdLike, integration_id: IdLike, skip: int = 0, limit: int = 50
    ) -> Tuple[List[IntegrationConnection], int]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        if await self._integrations.get_by_id_and_project(integration_id, project.id) is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        return await self._connections.list_by_integration(project.id, integration_id, skip=skip, limit=limit)

    async def list_for_subject(self, project_id: IdLike, subject: Subject) -> List[Tuple[IntegrationConnection, Integration]]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        stype, sid, _ = subject_parts(subject)
        rows: List[Tuple[IntegrationConnection, Integration]] = []
        for connection in await self._connections.list_for_subject(project.id, stype, sid):
            integration = await self._integrations.get_by_id_and_project(connection.integration_id, project.id)
            if integration is not None:
                rows.append((connection, integration))
        return rows

    async def active_integration_ids(self, project_id: IdLike, subject: Subject) -> set[str]:
        stype, sid, _ = subject_parts(subject)
        return {
            str(c.integration_id)
            for c in await self._connections.list_for_subject(project_id, stype, sid)
            if c.status == ConnectionStatus.ACTIVE
        }

    # -------------------------------------------------------------------- removal
    async def disconnect(self, project_id: IdLike, integration_id: IdLike, subject: Subject, actor_id: str, reason: str = "disconnect") -> bool:
        project = await self._lifecycle.get_active(project_id)
        _, _, skey = subject_parts(subject)
        connection = await self._connections.get(integration_id, skey)
        if connection is None or str(connection.project_id) != str(project.id):
            return False
        await self._remove(project.id, connection, actor_id, reason)
        return True

    async def revoke(self, project_id: IdLike, integration_id: IdLike, connection_id: IdLike, actor_id: str, reason: str = "admin_revoke") -> None:
        project = await self._lifecycle.get_active(project_id)
        connection = await self._connections.get_by_id(connection_id, project.id)
        if connection is None or str(connection.integration_id) != str(integration_id):
            raise NotFoundError("Connection not found")
        await self._remove(project.id, connection, actor_id, reason)

    async def _remove(self, project_id: Any, connection: IntegrationConnection, actor_id: str, reason: str) -> None:
        await self._revoke_upstream(str(project_id), connection)
        await self._connections.delete(connection.id)
        await self._audit.record(
            str(project_id),
            actor_id,
            ProjectAuditAction.CONNECTION_REVOKED.value,
            {"integration_id": str(connection.integration_id), "subject": connection.subject_key, "reason": reason},
        )

    async def _revoke_upstream(self, project_id: str, connection: IntegrationConnection) -> None:
        """Best-effort RFC 7009 revocation; local deletion always proceeds."""
        if connection.credential_kind != CredentialKind.OAUTH:
            return
        client = await self._clients.get_by_integration(connection.integration_id)
        if client is None:
            return
        try:
            iid = str(connection.integration_id)
            token = (
                await self._cipher.open(project_id, iid, connection.subject_key, "refresh", connection.refresh_envelope)
                if connection.refresh_envelope
                else await self._cipher.open(project_id, iid, connection.subject_key, "access", connection.access_envelope)
            )
            secret = (
                await self._cipher.open(project_id, iid, "client", "oauth_client_secret", client.client_secret_envelope)
                if client.client_secret_envelope
                else None
            )
            await self._oauth.revoke(client.revocation_endpoint, token, client.client_id, secret, client.token_endpoint_auth_method)
        except Exception:
            return

    async def revoke_all(self, project_id: str, integration_id: str, actor_id: str, reason: str) -> int:
        """Revoke upstream where possible and delete every connection (and the OAuth client) of an integration."""
        removed = 0
        while True:
            batch, _ = await self._connections.list_by_integration(project_id, integration_id, skip=0, limit=200)
            if not batch:
                break
            for connection in batch:
                await self._revoke_upstream(str(project_id), connection)
                await self._connections.delete(connection.id)
                removed += 1
        await self._clients.delete_by_integration(integration_id)
        if removed:
            await self._audit.record(
                str(project_id), actor_id, ProjectAuditAction.CONNECTION_REVOKED.value,
                {"integration_id": str(integration_id), "count": removed, "reason": reason},
            )
        return removed

    # -------------------------------------------------- EndUserConnectionPort
    async def suspend_subject(self, project_id: str, end_user_id: str) -> int:
        return await self._connections.set_status_for_subject(
            project_id, ConnectionSubjectType.END_USER, end_user_id, ConnectionStatus.ACTIVE, ConnectionStatus.SUSPENDED
        )

    async def resume_subject(self, project_id: str, end_user_id: str) -> int:
        return await self._connections.set_status_for_subject(
            project_id, ConnectionSubjectType.END_USER, end_user_id, ConnectionStatus.SUSPENDED, ConnectionStatus.ACTIVE
        )

    async def erase_subject(self, project_id: str, end_user_id: str) -> int:
        """Right to erasure: revoke upstream where possible, then delete the tokens synchronously."""
        for connection in await self._connections.list_for_subject(project_id, ConnectionSubjectType.END_USER, end_user_id):
            await self._revoke_upstream(project_id, connection)
        return await self._connections.delete_by_subject(project_id, ConnectionSubjectType.END_USER, end_user_id)


class ConnectionTokenService:
    """``ConnectionCredentialPort``: resolve (and refresh) the credential for exactly one subject."""

    def __init__(
        self,
        connection_repo: IConnectionRepository,
        oauth_client_repo: IOAuthClientRepository,
        integration_repo: IIntegrationRepository,
        cipher: TokenCipherPort,
        oauth: OAuthFlowPort,
        locks: KeyedLocks,
    ) -> None:
        self._connections = connection_repo
        self._clients = oauth_client_repo
        self._integrations = integration_repo
        self._cipher = cipher
        self._oauth = oauth
        self._locks = locks

    async def credentials_for(self, integration: Integration, subject: Subject) -> ResolvedCredentials:
        profile = integration.auth_profile
        # per_user: the caller's own connection only. project_shared: the project's connection, never a user's.
        effective = subject if profile.credential_mode == CredentialMode.PER_USER else Subject(SubjectType.PROJECT)
        _, _, skey = subject_parts(effective)
        connection = await self._connections.get(integration.id, skey)
        if connection is None:
            raise AuthRequired(integration, "connection_required")
        if connection.status != ConnectionStatus.ACTIVE:
            raise AuthRequired(integration, "reconnect_required")

        token = await self._access_token(integration, connection)
        if connection.last_used_at is None or datetime.now(timezone.utc) - _aware(connection.last_used_at) > LAST_USED_DEBOUNCE:
            await self._connections.touch_used(connection.id)
        return credentials_from_value(profile, connection.credential_kind, token)

    async def _access_token(self, integration: Integration, connection: IntegrationConnection) -> str:
        project_id, iid = str(integration.project_id), str(integration.id)
        if connection.credential_kind != CredentialKind.OAUTH or not self._due(connection):
            return await self._cipher.open(project_id, iid, connection.subject_key, "access", connection.access_envelope)

        async with self._locks.lock(f"refresh:{connection.id}"):
            current = await self._connections.get(integration.id, connection.subject_key)  # someone may have refreshed
            if current is None or current.status != ConnectionStatus.ACTIVE:
                raise AuthRequired(integration, "reconnect_required")
            if not self._due(current):
                return await self._cipher.open(project_id, iid, current.subject_key, "access", current.access_envelope)
            return await self._refresh(integration, current)

    @staticmethod
    def _due(connection: IntegrationConnection) -> bool:
        return connection.expires_at is not None and _aware(connection.expires_at) - datetime.now(timezone.utc) <= REFRESH_SKEW

    async def _refresh(self, integration: Integration, connection: IntegrationConnection) -> str:
        project_id, iid = str(integration.project_id), str(integration.id)
        if connection.refresh_envelope is None:
            await self._dead(integration, connection, "no_refresh_token")
            raise AuthRequired(integration, "reconnect_required")
        client = await self._clients.get_by_integration(integration.id)
        if client is None:
            await self._dead(integration, connection, "oauth_client_missing")
            raise AuthRequired(integration, "reconnect_required")

        refresh_token = await self._cipher.open(project_id, iid, connection.subject_key, "refresh", connection.refresh_envelope)
        secret = await self._client_secret(project_id, iid, client)
        try:
            tokens = await self._oauth.refresh(
                client.token_endpoint, refresh_token, client.client_id, secret, client.token_endpoint_auth_method, client.resource
            )
        except (OAuthInvalidGrant, OAuthInvalidClient) as exc:
            await self._dead(integration, connection, type(exc).__name__)
            raise AuthRequired(integration, "reconnect_required") from exc
        except OAuthFlowFailed as exc:
            raise UpstreamError("Token refresh failed; try again shortly") from exc  # transient: do not kill the grant

        access = await self._cipher.seal(project_id, iid, connection.subject_key, "access", tokens.access_token)
        new_refresh = (
            await self._cipher.seal(project_id, iid, connection.subject_key, "refresh", tokens.refresh_token)
            if tokens.refresh_token
            else connection.refresh_envelope  # servers may omit a new refresh token; keep the existing one
        )
        update: Dict[str, Any] = {
            "access_envelope": access,
            "refresh_envelope": new_refresh,
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=tokens.expires_in) if tokens.expires_in else None,
            "last_error": None,
        }
        if tokens.scopes:
            update["granted_scopes"] = tokens.scopes
        try:
            await self._connections.update_with_revision(connection.id, connection.revision, update)
        except Exception:
            # Lost a compare-and-swap race: the winner's credentials are authoritative; use our fresh token anyway.
            pass
        return tokens.access_token

    async def _client_secret(self, project_id: str, integration_id: str, client: IntegrationOAuthClient) -> Optional[str]:
        if client.client_secret_envelope is None:
            return None
        return await self._cipher.open(project_id, integration_id, "client", "oauth_client_secret", client.client_secret_envelope)

    async def _dead(self, integration: Integration, connection: IntegrationConnection, reason: str) -> None:
        """A dead grant stops retries: only this connection (and, if shared, the integration) needs attention."""
        await self._connections.set_status(connection.id, ConnectionStatus.NEEDS_AUTH, reason)
        if connection.subject_type == ConnectionSubjectType.PROJECT:
            await self._integrations.update_runtime_state(
                integration.id, integration.project_id, {"status": IntegrationStatus.NEEDS_AUTH, "status_reason": "Reconnect required"}
            )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
