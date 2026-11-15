"""
Project Credential Service implementing business logic, CSPRNG key generation,
one-time raw_key delivery, OCC lifecycle mutations, and audit log dispatch.
"""
from datetime import datetime, timezone
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.core.protocols.crypto import (
    DefaultEnvironmentPrefixStrategy,
    EnvironmentPrefixStrategy,
)
from app.core.protocols.repositories import (
    ICredentialRepository,
    IProjectAuditRepository,
    IProjectRepository,
)
from app.models.credential import CredentialStatus, ProjectCredential
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectStatus,
)
from app.repositories.credential_repository import (
    ProjectCredentialRepository,
    get_credential_repository,
)
from app.repositories.project_audit_repository import (
    ProjectAuditRepository,
    get_project_audit_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.schemas.credential import (
    CredentialCreateRequest,
    CredentialCreateResponse,
    CredentialResponse,
    CredentialRevokeRequest,
)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure datetime is UTC timezone-aware for reliable comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class CredentialKeyGenerator:
    """
    Dedicated generator for 256-bit CSPRNG API keys, SHA-256 hashes,
    and non-sensitive preview hints using an EnvironmentPrefixStrategy.
    """

    def __init__(self, prefix_strategy: Optional[EnvironmentPrefixStrategy] = None) -> None:
        self.prefix_strategy: EnvironmentPrefixStrategy = prefix_strategy or DefaultEnvironmentPrefixStrategy()

    def generate(self, environment: str) -> Tuple[str, str, str]:
        """
        Generate (raw_key, key_hash, masked_key).
        Prefix is determined by the configured EnvironmentPrefixStrategy.
        """
        prefix = self.prefix_strategy.get_prefix(environment)
        entropy = secrets.token_urlsafe(32)  # 256-bit entropy, 43 url-safe base64 chars
        raw_key = f"{prefix}{entropy}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        masked_key = f"{prefix}{entropy[:4]}...{entropy[-4:]}"
        return raw_key, key_hash, masked_key


def generate_api_key(environment: str) -> Tuple[str, str, str]:
    """
    Backward-compatible helper delegating to CredentialKeyGenerator.
    Generate a 256-bit CSPRNG API key, SHA-256 hash, and masked preview hint.
    """
    return CredentialKeyGenerator().generate(environment)


class ProjectCredentialService:
    """
    Domain service orchestrating credential lifecycle, zero-plaintext storage,
    optimistic concurrency control (OCC), and immutable audit log dispatch.
    Decoupled from HTTP transports and concrete repository implementations.
    """

    def __init__(
        self,
        credential_repo: Optional[ICredentialRepository] = None,
        project_repo: Optional[IProjectRepository] = None,
        audit_repo: Optional[IProjectAuditRepository] = None,
        key_generator: Optional[CredentialKeyGenerator] = None,
    ) -> None:
        self.credential_repo: ICredentialRepository = (
            credential_repo if credential_repo is not None else get_credential_repository()
        )
        self.project_repo: IProjectRepository = (
            project_repo if project_repo is not None else get_project_repository()
        )
        self.audit_repo: IProjectAuditRepository = (
            audit_repo if audit_repo is not None else get_project_audit_repository()
        )
        self.key_generator: CredentialKeyGenerator = key_generator or CredentialKeyGenerator()

    async def _get_active_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        allow_archived: bool = False,
    ) -> Project:
        """
        Validate project existence and enforce lifecycle state constraints.
        Raises NotFoundError if not found.
        Raises ProjectPurgedError if purged.
        Raises ProjectDeletedError if soft deleted.
        Raises ProjectArchivedError if archived and allow_archived is False.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if not project:
            raise NotFoundError(f"Project '{project_id}' not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.ARCHIVED and not allow_archived:
            raise ProjectArchivedError(str(project.id))

        return project

    async def create_credential(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: CredentialCreateRequest,
        actor_id: str,
    ) -> CredentialCreateResponse:
        """
        Generate a new machine API credential and persist its irreversible hash.
        raw_key is returned strictly once in this response and never stored.
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        if not request.scopes:
            raise BadRequestError("Scopes list cannot be empty")

        now = datetime.now(timezone.utc)
        expires_at_utc = _ensure_utc(request.expires_at)
        if expires_at_utc is not None and expires_at_utc <= now:
            raise BadRequestError("Expiration timestamp must be in the future")

        env = request.environment.strip() if request.environment else "production"
        raw_key, key_hash, masked_key = self.key_generator.generate(env)
        prefix = self.key_generator.prefix_strategy.get_prefix(env)

        credential = ProjectCredential(
            project_id=project.id,
            name=request.name.strip(),
            description=request.description.strip() if request.description else None,
            environment=env,
            key_prefix=prefix,
            masked_key=masked_key,
            key_hash=key_hash,
            scopes=request.scopes,
            rate_limit_rpm=request.rate_limit_rpm,
            status=CredentialStatus.ACTIVE,
            revision=1,
            expires_at=expires_at_utc,
            revoked_at=None,
            revoked_by=None,
            last_used_at=None,
            last_used_ip=None,
            total_uses=0,
            is_deleted=False,
            deleted_at=None,
            created_by=actor_id,
            updated_by=actor_id,
        )

        created = await self.credential_repo.create(credential)

        # Audit log dispatch
        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.CREDENTIAL_CREATED,
            payload={
                "credential_id": str(created.id),
                "name": created.name,
                "environment": created.environment,
                "scopes": created.scopes,
                "revision": created.revision,
                "rate_limit_rpm": created.rate_limit_rpm,
                "expires_at": created.expires_at.isoformat() if created.expires_at else None,
            },
        )

        base_response = CredentialResponse.from_model(created)
        return CredentialCreateResponse(
            **base_response.model_dump(),
            raw_key=raw_key,
        )

    async def list_credentials(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: Optional[str] = None,
        status: Optional[CredentialStatus] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[CredentialResponse], int]:
        """
        List credential metadata for a project.
        Read operations are permitted on ARCHIVED projects.
        Never reveals raw_key.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        items, total = await self.credential_repo.list_by_project(
            project_id=project.id,
            environment=environment,
            status=status,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit,
            include_deleted=False,
        )
        responses = [CredentialResponse.from_model(item) for item in items]
        return responses, total

    async def get_credential(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        credential_id: Union[str, PydanticObjectId, ObjectId],
    ) -> CredentialResponse:
        """
        Inspect metadata for a single credential.
        Read operations are permitted on ARCHIVED projects.
        Never reveals raw_key.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        credential = await self.credential_repo.get_by_id_and_project(
            credential_id=credential_id,
            project_id=project.id,
            include_deleted=False,
        )
        if credential is None:
            raise NotFoundError(f"Credential '{credential_id}' not found")

        return CredentialResponse.from_model(credential)

    async def revoke_credential(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        credential_id: Union[str, PydanticObjectId, ObjectId],
        request: CredentialRevokeRequest,
        actor_id: str,
    ) -> CredentialResponse:
        """
        Immediately revoke an active credential, rendering it permanently unusable for authentication.
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        existing = await self.credential_repo.get_by_id_and_project(
            credential_id=credential_id,
            project_id=project.id,
            include_deleted=False,
        )
        if existing is None:
            raise NotFoundError(f"Credential '{credential_id}' not found")
        if existing.status == CredentialStatus.REVOKED:
            raise ConflictError("Credential is already revoked")

        now = datetime.now(timezone.utc)
        updated = await self.credential_repo.revoke(
            credential_id=credential_id,
            project_id=project.id,
            expected_revision=request.expected_revision,
            revoked_by=actor_id,
        )

        # Audit log dispatch
        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.CREDENTIAL_REVOKED,
            payload={
                "credential_id": str(updated.id),
                "name": updated.name,
                "reason": request.reason,
                "revoked_at": now.isoformat(),
                "revision": updated.revision,
            },
        )

        return CredentialResponse.from_model(updated)

    async def delete_credential(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        credential_id: Union[str, PydanticObjectId, ObjectId],
        purge: bool = False,
        actor_id: str = "",
    ) -> Dict[str, Any]:
        """
        Delete a credential:
        - If purge=False: soft-delete (sets is_deleted=True).
        - If purge=True: permanent deletion (only permitted on soft-deleted or revoked keys).
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        existing = await self.credential_repo.get_by_id_and_project(
            credential_id=credential_id,
            project_id=project.id,
            include_deleted=True,
        )
        if existing is None:
            raise NotFoundError(f"Credential '{credential_id}' not found")

        if purge:
            if not existing.is_deleted and existing.status != CredentialStatus.REVOKED:
                raise ConflictError("Only soft-deleted or revoked credentials can be purged")

            deleted = await self.credential_repo.purge(credential_id, project.id)
            if not deleted:
                raise NotFoundError(f"Credential '{credential_id}' not found")

            await self.audit_repo.log_event(
                project_id=project.id,
                actor_id=actor_id,
                action=ProjectAuditAction.CREDENTIAL_PURGED,
                payload={
                    "credential_id": str(existing.id),
                    "name": existing.name,
                },
            )
            return {
                "message": f"Credential '{credential_id}' permanently purged",
                "purged": True,
            }

        # Soft delete
        if existing.is_deleted:
            raise ConflictError("Credential is already deleted")

        deleted = await self.credential_repo.soft_delete(credential_id, project.id)
        if not deleted:
            raise NotFoundError(f"Credential '{credential_id}' not found")

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.CREDENTIAL_DELETED,
            payload={
                "credential_id": str(existing.id),
                "name": existing.name,
            },
        )
        return {
            "message": f"Credential '{credential_id}' successfully soft-deleted",
            "deleted": True,
        }


def get_credential_service(
    credential_repo: ProjectCredentialRepository = Depends(get_credential_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
) -> ProjectCredentialService:
    """Dependency injection provider for ProjectCredentialService."""
    return ProjectCredentialService(
        credential_repo=credential_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
    )
