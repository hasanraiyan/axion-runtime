"""Shared plumbing for Module 07 services: lifecycle guard, audit adapter, secret reader."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.crypto import CryptoService
from app.core.exceptions import (
    BadRequestError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.core.protocols.repositories import IProjectAuditRepository, IProjectRepository, ISecretRepository
from app.models.project import Project, ProjectAuditAction, ProjectStatus

IdLike = Union[str, PydanticObjectId, ObjectId]


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class ProjectLifecycle:
    """Enforces the project boundary and lifecycle state (MOD-01 semantics)."""

    def __init__(self, project_repo: IProjectRepository) -> None:
        self._projects = project_repo

    async def get_active(self, project_id: IdLike, allow_archived: bool = False) -> Project:
        project = await self._projects.get_by_id_or_slug(project_id)
        if project is None:
            raise NotFoundError(f"Project '{project_id}' not found")
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.ARCHIVED and not allow_archived:
            raise ProjectArchivedError(str(project.id))
        return project


class ProjectAuditAdapter:
    """``AuditPort`` backed by the project audit repository."""

    def __init__(self, audit_repo: IProjectAuditRepository) -> None:
        self._audit = audit_repo

    async def record(self, project_id: str, actor_id: str, action: str, payload: Dict[str, Any]) -> None:
        await self._audit.log_event(
            project_id=project_id, actor_id=actor_id, action=ProjectAuditAction(action), payload=payload
        )


class ProjectSecretReader:
    """
    ``SecretReaderPort`` that decrypts MOD-02 secrets into memory. A missing, deleted, or
    foreign secret is reported as not found (anti-enumeration); plaintext is returned only
    to the caller and never logged.
    """

    def __init__(
        self, secret_repo: ISecretRepository, crypto: CryptoService, environment: str = "production"
    ) -> None:
        self._secrets = secret_repo
        self._crypto = crypto
        self._environment = environment

    async def read(self, project_id: str, secret_id: str) -> str:
        secret = await self._secrets.get_by_id_and_project(secret_id, project_id)
        if secret is None or secret.is_deleted:
            raise NotFoundError("Referenced secret not found")
        return await self._crypto.decrypt_secret(secret.envelope, str(project_id), secret.environment, secret.name)

    async def read_by_name(self, project_id: str, name: str) -> Optional[str]:
        matches = await self._secrets.find_by_names(
            project_id=project_id, environment=self._environment, names=[name], include_deleted=False
        )
        if not matches:
            return None
        secret = matches[0]
        return await self._crypto.decrypt_secret(secret.envelope, str(project_id), secret.environment, secret.name)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BadRequestError(message)
