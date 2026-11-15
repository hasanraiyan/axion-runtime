"""
EndUserService (SRS-07 FR-70, FR-71, FR-79): the end-user anchor, session tokens, block and erasure.

Axion does not authenticate end users. A trusted project backend asserts them (FR-70); this
service records the assertion, enforces blocks, and mints short-lived, narrowly scoped session
tokens. It never authorizes tool access (that is ``ToolAccessService``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, EndUserBlockedError, NotFoundError
from app.core.protocols.tool_repositories import IEndUserRepository, IToolInvocationRepository
from app.core.tools.events import EndUserBlocked, ToolsetChanged
from app.core.tools.ports import AuditPort, DomainEventPort, EndUserConnectionPort
from app.core.tools.signing import TokenSigner
from app.core.tools.types import Subject, SubjectType
from app.models.end_user import EndUserStatus, ProjectEndUser
from app.models.project import ProjectAuditAction
from app.schemas.tools import EndUserAssertRequest
from app.services.tools.common import ProjectLifecycle

IdLike = Union[str, PydanticObjectId, ObjectId]
SESSION_PURPOSE = "end_user_session"
ALLOWED_CAPABILITIES = {"connections:own", "apps:use"}
MAX_ATTRIBUTES = 20


def _validate_attributes(attributes: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if attributes is None:
        return None
    if len(attributes) > MAX_ATTRIBUTES:
        raise BadRequestError(f"At most {MAX_ATTRIBUTES} attributes are allowed")
    for key, value in attributes.items():
        if not key.replace("_", "").isalnum() or key in ("id", "external_id") or len(key) > 40:
            raise BadRequestError(f"Attribute name '{key[:40]}' is not allowed")
        if not isinstance(value, str) or len(value) > 500:
            raise BadRequestError(f"Attribute '{key}' must be a string of at most 500 characters")
    return attributes


class EndUserService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        end_user_repo: IEndUserRepository,
        signer: TokenSigner,
        audit: AuditPort,
        events: DomainEventPort,
        invocation_repo: Optional[IToolInvocationRepository] = None,
        connections: Optional[EndUserConnectionPort] = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._end_users = end_user_repo
        self._signer = signer
        self._audit = audit
        self._events = events
        self._invocations = invocation_repo
        self._connections = connections

    # --------------------------------------------------------------- assertion
    async def assert_user(
        self, project_id: IdLike, external_id: str, request: Optional[EndUserAssertRequest], actor_id: str
    ) -> Tuple[ProjectEndUser, bool]:
        """Upsert an end user asserted by a trusted caller. Returns ``(end_user, created)``."""
        project = await self._lifecycle.get_active(project_id)
        external_id = external_id.strip()
        if not external_id or len(external_id) > 255 or any(c in external_id for c in "\r\n\t\x00"):
            raise BadRequestError("Invalid end user identifier")
        request = request or EndUserAssertRequest()
        user, created = await self._end_users.upsert_seen(
            project.id,
            external_id,
            request.display_name,
            request.email,
            _validate_attributes(request.attributes),
        )
        if user.status == EndUserStatus.DELETED:
            user = await self._end_users.update_status(project.id, external_id, EndUserStatus.ACTIVE)
            created = True
        if created:
            await self._audit.record(
                str(project.id), actor_id, ProjectAuditAction.END_USER_CREATED.value, {"end_user_id": str(user.id)}
            )
        return user, created

    async def resolve_subject(self, project_id: IdLike, external_id: str, actor_id: str) -> Subject:
        """Assert (just in time) and return the subject; blocked end users are refused."""
        user, _ = await self.assert_user(project_id, external_id, None, actor_id)
        if user.status == EndUserStatus.BLOCKED:
            raise EndUserBlockedError()
        return Subject(
            type=SubjectType.END_USER, id=str(user.id), external_id=user.external_id, attributes=dict(user.attributes)
        )

    async def ensure_active(self, project_id: IdLike, end_user_id: str) -> None:
        """Gateway re-check: a user blocked after toolset resolution must not run tools."""
        user = await self._end_users.get_by_id_and_project(end_user_id, project_id)
        if user is None or user.status != EndUserStatus.ACTIVE:
            raise EndUserBlockedError()

    # ---------------------------------------------------------------- management
    async def get(self, project_id: IdLike, external_id: str) -> ProjectEndUser:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        user = await self._end_users.get_by_external_id(project.id, external_id)
        if user is None or user.status == EndUserStatus.DELETED:
            raise NotFoundError("End user not found")
        return user

    async def list(
        self,
        project_id: IdLike,
        status: Optional[EndUserStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectEndUser], int]:
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        return await self._end_users.list_by_project(project.id, status=status, search=search, skip=skip, limit=limit)

    async def block(self, project_id: IdLike, external_id: str, actor_id: str) -> ProjectEndUser:
        project = await self._lifecycle.get_active(project_id)
        await self.get(project.id, external_id)
        user = await self._end_users.update_status(project.id, external_id, EndUserStatus.BLOCKED)
        if self._connections is not None:
            await self._connections.suspend_subject(str(project.id), str(user.id))
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.END_USER_BLOCKED.value, {"end_user_id": str(user.id)}
        )
        await self._events.publish(EndUserBlocked(str(project.id), str(user.id)))
        await self._events.publish(ToolsetChanged(str(project.id), "end_user_blocked"))
        return user

    async def unblock(self, project_id: IdLike, external_id: str, actor_id: str) -> ProjectEndUser:
        project = await self._lifecycle.get_active(project_id)
        await self.get(project.id, external_id)
        user = await self._end_users.update_status(project.id, external_id, EndUserStatus.ACTIVE)
        if self._connections is not None:
            await self._connections.resume_subject(str(project.id), str(user.id))
        await self._audit.record(
            str(project.id), actor_id, ProjectAuditAction.END_USER_UNBLOCKED.value, {"end_user_id": str(user.id)}
        )
        return user

    async def delete(self, project_id: IdLike, external_id: str, actor_id: str) -> None:
        """Erase an end user: mark deleted and scrub their identity from invocation records (FR-79)."""
        project = await self._lifecycle.get_active(project_id)
        existing = await self.get(project.id, external_id)
        user = await self._end_users.update_status(project.id, external_id, EndUserStatus.DELETED)
        erased_connections = 0
        if self._connections is not None:
            erased_connections = await self._connections.erase_subject(str(project.id), str(existing.id))
        scrubbed = 0
        if self._invocations is not None:
            scrubbed = await self._invocations.scrub_subject(project.id, str(existing.id))
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.END_USER_DELETED.value,
            {"end_user_id": str(user.id), "invocation_records_scrubbed": scrubbed, "connections_erased": erased_connections},
        )
        await self._events.publish(EndUserBlocked(str(project.id), str(user.id)))

    # ----------------------------------------------------------------- sessions
    async def mint_session(
        self,
        project_id: IdLike,
        external_id: str,
        ttl_seconds: int,
        capabilities: List[str],
        actor_id: str,
    ) -> Tuple[str, str]:
        """Mint a short-lived session token for one end user (FR-71). Returns ``(token, end_user_id)``."""
        invalid = [c for c in capabilities if c not in ALLOWED_CAPABILITIES]
        if invalid:
            raise BadRequestError(f"Unsupported capability: {invalid[0]}")
        subject = await self.resolve_subject(project_id, external_id, actor_id)
        project = await self._lifecycle.get_active(project_id)
        token = self._signer.sign(
            SESSION_PURPOSE,
            {"prj": str(project.id), "eu": subject.id, "ext": subject.external_id, "cap": sorted(set(capabilities))},
            ttl_seconds,
        )
        return token, str(subject.id)

    async def verify_session(self, token: str, project_id: IdLike) -> Dict[str, Any]:
        """Verify a session token and that its end user is still active and in this project."""
        claims = self._signer.verify(token, SESSION_PURPOSE)
        project = await self._lifecycle.get_active(project_id, allow_archived=True)
        if claims.get("prj") != str(project.id):
            from app.core.exceptions import UnauthorizedError

            raise UnauthorizedError("Invalid token")
        await self.ensure_active(project.id, str(claims.get("eu")))
        return claims
