"""
Project Secret Service implementing core domain business rules, in-place OCC replacement,
lifecycle guards, privileged reveal, and immutable audit logging.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.crypto import CryptoService, get_crypto_service
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
    SecretInUseError,
)
from app.core.protocols.repositories import IProjectProviderRepository
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectStatus,
)
from app.models.secret import ProjectSecret
from app.repositories.project_audit_repository import (
    ProjectAuditRepository,
    get_project_audit_repository,
)
from app.repositories.project_provider_repository import (
    ProjectProviderRepository,
    get_project_provider_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.repositories.secret_repository import (
    ProjectSecretRepository,
    get_secret_repository,
)
from app.schemas.secret import (
    SecretCreateRequest,
    SecretResponse,
    SecretRotateRequest,
    SecretSummaryResponse,
    SecretUpdateRequest,
    SecretValueResponse,
)


class ProjectSecretService:
    """
    Domain service orchestrating secret lifecycle, zero-plaintext storage,
    in-place rotation, optimistic locking, and audit dispatch.
    Decoupled from HTTP transports.
    """

    def __init__(
        self,
        secret_repo: Optional[ProjectSecretRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
        audit_repo: Optional[ProjectAuditRepository] = None,
        crypto_service: Optional[CryptoService] = None,
        provider_repo: Optional[IProjectProviderRepository] = None,
    ) -> None:
        self.secret_repo = secret_repo if secret_repo is not None else get_secret_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.crypto_service = crypto_service if crypto_service is not None else get_crypto_service()
        self.provider_repo = provider_repo if provider_repo is not None else get_project_provider_repository()

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

    async def create_secret(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: SecretCreateRequest,
        actor_id: str,
    ) -> SecretResponse:
        """
        Create and encrypt a new secret with zero plaintext persistence.
        Initializes OCC revision to 1 and logs SECRET_CREATED audit event.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        env = request.environment.strip() if request.environment else "production"

        # Check unique constraint within active secrets
        exists = await self.secret_repo.check_exists(project.id, env, request.name)
        if exists:
            raise ConflictError(f"Secret '{request.name}' already exists in environment '{env}'")

        # Encrypt value with fresh 256-bit DEK, nonce, and canonical AAD
        envelope = await self.crypto_service.encrypt_secret(
            request.value.get_secret_value(),
            str(project.id),
            env,
            request.name,
        )

        secret = ProjectSecret(
            project_id=project.id,
            name=request.name,
            environment=env,
            description=request.description,
            tags=request.tags,
            is_system=False,
            envelope=envelope,
            revision=1,
            last_rotated_at=None,
            expires_at=request.expires_at,
            is_deleted=False,
            deleted_at=None,
            created_by=actor_id,
            updated_by=actor_id,
        )

        created = await self.secret_repo.create(secret)

        # Audit log event
        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_CREATED,
            payload={
                "secret_id": str(created.id),
                "name": created.name,
                "environment": created.environment,
                "tags": created.tags,
                "revision": created.revision,
            },
        )

        return SecretResponse.from_model(created)

    async def list_secrets(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[SecretSummaryResponse], int]:
        """
        List secret metadata for a project.
        Zero plaintext or ciphertext is included in the response.
        Read operations are permitted on ARCHIVED projects.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        items, total = await self.secret_repo.list_by_project(
            project_id=project.id,
            environment=environment,
            search=search,
            tags=tags,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit,
            include_deleted=False,
        )
        summaries = [SecretSummaryResponse.model_validate(item) for item in items]
        return summaries, total

    async def get_secret_metadata(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
    ) -> SecretResponse:
        """
        Inspect metadata for a single secret.
        Zero plaintext is returned.
        Read operations are permitted on ARCHIVED projects.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        return SecretResponse.from_model(secret)

    async def update_secret(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
        request: SecretUpdateRequest,
        actor_id: str,
    ) -> SecretResponse:
        """
        Update secret metadata or replace value in-place with OCC revision enforcement.
        If a new value is provided, permanently overwrites the encrypted envelope with a
        freshly generated DEK and nonce, and updates last_rotated_at.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        update_dict: Dict[str, Any] = {"updated_by": actor_id}
        if "description" in request.model_fields_set:
            update_dict["description"] = request.description
        if "tags" in request.model_fields_set and request.tags is not None:
            update_dict["tags"] = request.tags
        if "expires_at" in request.model_fields_set:
            update_dict["expires_at"] = request.expires_at

        value_replaced = False
        if request.value is not None:
            value_replaced = True
            new_envelope = await self.crypto_service.encrypt_secret(
                request.value.get_secret_value(),
                str(project.id),
                secret.environment,
                secret.name,
            )
            update_dict["envelope"] = new_envelope
            update_dict["last_rotated_at"] = datetime.now(timezone.utc)

        updated = await self.secret_repo.update_with_revision(
            secret_id=secret.id,
            project_id=project.id,
            expected_revision=request.revision,
            update_dict=update_dict,
        )

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_UPDATED,
            payload={
                "secret_id": str(updated.id),
                "name": updated.name,
                "environment": updated.environment,
                "revision": updated.revision,
                "value_replaced": value_replaced,
            },
        )

        return SecretResponse.from_model(updated)

    async def rotate_secret(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
        request: SecretRotateRequest,
        actor_id: str,
    ) -> SecretResponse:
        """
        Rotate a secret value in-place with a freshly generated 256-bit DEK,
        updating last_rotated_at and incrementing the OCC revision counter.
        Zero historical version records are retained.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        new_envelope = await self.crypto_service.encrypt_secret(
            request.new_value.get_secret_value(),
            str(project.id),
            secret.environment,
            secret.name,
        )

        now = datetime.now(timezone.utc)
        update_dict: Dict[str, Any] = {
            "envelope": new_envelope,
            "last_rotated_at": now,
            "updated_by": actor_id,
        }

        rotated = await self.secret_repo.update_with_revision(
            secret_id=secret.id,
            project_id=project.id,
            expected_revision=request.revision,
            update_dict=update_dict,
        )

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_ROTATED,
            payload={
                "secret_id": str(rotated.id),
                "name": rotated.name,
                "environment": rotated.environment,
                "revision": rotated.revision,
            },
        )

        return SecretResponse.from_model(rotated)

    async def delete_secret(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> bool:
        """
        Soft-delete a secret. The secret is immediately excluded from active listings
        and runtime resolutions. Emits SECRET_DELETED audit event.
        Enforces Secret Unlink Invariant (FR-08): cannot delete if referenced by active provider.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        # FR-08 Secret Unlink Invariant
        if self.provider_repo is not None:
            active_count = await self.provider_repo.count_by_secret_id(secret.id, include_deleted=False)
            if active_count > 0:
                raise SecretInUseError(secret_id=str(secret.id), count=active_count)

        success = await self.secret_repo.soft_delete(secret_id, project.id)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_DELETED,
            payload={
                "secret_id": str(secret.id),
                "name": secret.name,
                "environment": secret.environment,
            },
        )

        return success

    async def purge_secret(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> bool:
        """
        Permanently delete a secret document from the collection.
        Emits SECRET_PURGED audit event.
        Enforces Secret Unlink Invariant (FR-08): cannot purge if referenced by active provider.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id, include_deleted=True)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        # FR-08 Secret Unlink Invariant
        if self.provider_repo is not None:
            active_count = await self.provider_repo.count_by_secret_id(secret.id, include_deleted=False)
            if active_count > 0:
                raise SecretInUseError(secret_id=str(secret.id), count=active_count)

        purged = await self.secret_repo.purge(secret_id, project.id)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_PURGED,
            payload={
                "secret_id": str(secret.id),
                "name": secret.name,
                "environment": secret.environment,
            },
        )

        return purged

    async def reveal_secret_value(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        reason: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> SecretValueResponse:
        """
        Privileged plaintext reveal. Permitted on ACTIVE or ARCHIVED projects for compliance.
        Decrypts ciphertext in-memory and emits immutable SECRET_REVEALED audit event.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project.id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found")

        plaintext = await self.crypto_service.decrypt_secret(
            secret.envelope,
            str(project.id),
            secret.environment,
            secret.name,
        )

        audit_payload: Dict[str, Any] = {
            "secret_id": str(secret.id),
            "secret_name": secret.name,
            "environment": secret.environment,
        }
        if reason:
            audit_payload["reason"] = reason
        if client_ip:
            audit_payload["client_ip"] = client_ip
        if user_agent:
            audit_payload["user_agent"] = user_agent

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.SECRET_REVEALED,
            payload=audit_payload,
        )

        return SecretValueResponse(
            id=str(secret.id),
            name=secret.name,
            environment=secret.environment,
            value=plaintext,
            revealed_at=datetime.now(timezone.utc),
            audit_logged=True,
        )


def get_secret_service(
    secret_repo: ProjectSecretRepository = Depends(get_secret_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    crypto_service: CryptoService = Depends(get_crypto_service),
    provider_repo: ProjectProviderRepository = Depends(get_project_provider_repository),
) -> ProjectSecretService:
    """FastAPI dependency provider for ProjectSecretService."""
    return ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=crypto_service,
        provider_repo=provider_repo,
    )
