from typing import List, Type
from beanie import Document
from app.models.user import User, UserRole
from app.models.project import (
    Project,
    ProjectMember,
    ProjectAuditLog,
    ProjectStatus,
    ProjectRole,
    ProjectAuditAction,
    ProjectSettings,
)
from app.models.secret import (
    ProjectSecret,
    EncryptedEnvelope,
)
from app.models.credential import (
    ProjectCredential,
    CredentialStatus,
)

# Registry of all Beanie document models for initialization.
DOCUMENT_MODELS: List[Type[Document]] = [
    User,
    Project,
    ProjectMember,
    ProjectAuditLog,
    ProjectSecret,
    ProjectCredential,
]

__all__ = [
    "User",
    "UserRole",
    "Project",
    "ProjectMember",
    "ProjectAuditLog",
    "ProjectStatus",
    "ProjectRole",
    "ProjectAuditAction",
    "ProjectSettings",
    "ProjectSecret",
    "EncryptedEnvelope",
    "ProjectCredential",
    "CredentialStatus",
    "DOCUMENT_MODELS",
]
