"""
Runtime Secret Resolver providing batch in-memory decryption for agent workers,
sandboxes, workflow nodes, and template interpolation for {{secrets.VAR_NAME}}.
"""
from datetime import datetime, timezone
import inspect
import re
from typing import Any, Dict, List, Optional, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.crypto import CryptoService, get_crypto_service
from app.core.exceptions import (
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.models.project import Project, ProjectAuditAction, ProjectStatus
from app.repositories.project_audit_repository import (
    ProjectAuditRepository,
    get_project_audit_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.repositories.secret_repository import (
    ProjectSecretRepository,
    get_secret_repository,
)
from app.schemas.secret import SecretBatchResolveResponse


async def _maybe_await(val: Any) -> Any:
    """Helper to evaluate both synchronous returns and awaitable objects."""
    if inspect.isawaitable(val):
        return await val
    return val


class RuntimeSecretResolver:
    """
    Engine-agnostic runtime resolver providing in-memory decrypted secret dictionaries
    and configuration template interpolation for workflow and sandbox executions.
    """

    def __init__(
        self,
        secret_repo: Optional[ProjectSecretRepository] = None,
        project_repo: Optional[ProjectRepository] = None,
        audit_repo: Optional[ProjectAuditRepository] = None,
        crypto_service: Optional[CryptoService] = None,
    ) -> None:
        self.secret_repo = secret_repo if secret_repo is not None else get_secret_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.crypto_service = crypto_service if crypto_service is not None else get_crypto_service()

    async def _get_active_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
    ) -> Project:
        """
        Validate that the target project is ACTIVE.
        Runtime secret resolution is rejected on ARCHIVED, SOFT_DELETED, or PURGED projects.
        """
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if not project:
            raise NotFoundError(f"Project '{project_id}' not found")

        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.ARCHIVED:
            raise ProjectArchivedError(str(project.id))

        return project

    async def resolve_secrets(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        names: List[str],
        environment: str = "production",
        execution_id: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> SecretBatchResolveResponse:
        """
        Batch resolves decrypted plaintext secrets for runtime processes.
        Excludes expired secrets, logs SECRET_ACCESSED audit event,
        and returns {resolved: {...}, missing: [...]}.
        """
        project = await self._get_active_project(project_id)

        # Query active matching secrets from repository
        matched_secrets = await self.secret_repo.find_by_names(
            project_id=project.id,
            environment=environment,
            names=names,
            include_deleted=False,
        )

        now = datetime.now(timezone.utc)
        resolved: Dict[str, str] = {}

        for secret in matched_secrets:
            # Check expiration: exclude if expired
            if secret.expires_at is not None:
                expires_at = secret.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at <= now:
                    continue

            # In-memory AES-256-GCM decryption
            plaintext = await _maybe_await(
                self.crypto_service.decrypt_secret(
                    secret.envelope,
                    str(project.id),
                    secret.environment,
                    secret.name,
                )
            )
            resolved[secret.name] = plaintext

        missing = [name for name in names if name not in resolved]

        # Immutable audit logging (names only, ZERO PLAINTEXT)
        audit_payload: Dict[str, Any] = {
            "environment": environment,
            "resolved_keys": list(resolved.keys()),
            "missing_keys": missing,
        }
        if execution_id:
            audit_payload["execution_id"] = execution_id

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id or "system",
            action=ProjectAuditAction.SECRET_ACCESSED,
            payload=audit_payload,
        )

        return SecretBatchResolveResponse(resolved=resolved, missing=missing)

    @staticmethod
    def extract_template_placeholders(template_str: str) -> List[str]:
        """
        Extract all {{secrets.VAR_NAME}} variable names from a template string.
        """
        matches = re.findall(r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}", template_str)
        return sorted(list(set(matches)))

    @staticmethod
    def interpolate_templates(template_str: str, secrets_map: Dict[str, str]) -> str:
        """
        Replace {{secrets.VAR_NAME}} placeholders with their decrypted values.
        If a key is missing from secrets_map, leaves the placeholder untouched.
        """
        return re.sub(
            r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}",
            lambda m: secrets_map.get(m.group(1), m.group(0)),
            template_str,
        )

    async def resolve_and_interpolate(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        template_str: str,
        environment: str = "production",
        execution_id: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> str:
        """
        Convenience method: extracts placeholders from template_str,
        batch resolves them, and returns the interpolated string.
        """
        placeholders = self.extract_template_placeholders(template_str)
        if not placeholders:
            return template_str

        batch_result = await self.resolve_secrets(
            project_id=project_id,
            names=placeholders,
            environment=environment,
            execution_id=execution_id,
            actor_id=actor_id,
        )
        return self.interpolate_templates(template_str, batch_result.resolved)


def get_runtime_secret_resolver(
    secret_repo: ProjectSecretRepository = Depends(get_secret_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    crypto_service: CryptoService = Depends(get_crypto_service),
) -> RuntimeSecretResolver:
    """FastAPI dependency provider for RuntimeSecretResolver."""
    return RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=crypto_service,
    )
