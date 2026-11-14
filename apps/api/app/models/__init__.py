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

# Registry of all Beanie document models for initialization.
DOCUMENT_MODELS: List[Type[Document]] = [
    User,
    Project,
    ProjectMember,
    ProjectAuditLog,
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
    "DOCUMENT_MODELS",
]
