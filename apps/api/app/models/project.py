from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from beanie import PydanticObjectId
from pymongo import ASCENDING, DESCENDING, TEXT, IndexModel
from pydantic import BaseModel, Field

from app.db.base import BaseDocument


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    SOFT_DELETED = "soft_deleted"
    PURGED = "purged"


class ProjectRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class ProjectAuditAction(str, Enum):
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_ARCHIVED = "project.archived"
    PROJECT_UNARCHIVED = "project.unarchived"
    PROJECT_RESTORED = "project.restored"
    PROJECT_DELETED = "project.deleted"
    PROJECT_PURGED = "project.purged"
    MEMBER_ADDED = "member.added"
    MEMBER_ROLE_UPDATED = "member.role_updated"
    MEMBER_REMOVED = "member.removed"
    OWNERSHIP_TRANSFERRED = "ownership.transferred"
    SECRET_CREATED = "secret.created"
    SECRET_UPDATED = "secret.updated"
    SECRET_DELETED = "secret.deleted"
    SECRET_ROTATED = "secret.rotated"
    SECRET_ACCESSED = "secret.accessed"
    SECRET_REVEALED = "secret.revealed"
    SECRET_PURGED = "secret.purged"
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_UPDATED = "credential.updated"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_DELETED = "credential.deleted"
    CREDENTIAL_PURGED = "credential.purged"
    PROVIDER_CREATED = "provider.created"
    PROVIDER_UPDATED = "provider.updated"
    PROVIDER_HEALTHCHECK = "provider.healthcheck"
    PROVIDER_DELETED = "provider.deleted"
    PROVIDER_PURGED = "provider.purged"
    MODEL_CREATED = "model.created"
    MODEL_UPDATED = "model.updated"
    MODEL_DELETED = "model.deleted"
    MODEL_PURGED = "model.purged"
    ROUTING_FALLBACK = "routing.fallback"


class ProjectSettings(BaseModel):
    default_environment: str = Field(default="production", description="Default environment context")
    notifications_enabled: bool = Field(default=True, description="Enable notification hooks")
    retention_days: int = Field(default=30, ge=1, le=365, description="Retention grace period in days for soft-deleted projects")
    custom_settings: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary custom settings")


class Project(BaseDocument):
    name: str = Field(..., min_length=2, max_length=100, description="Display name of the project")
    slug: str = Field(..., min_length=2, max_length=100, description="URL-safe unique project slug")
    description: Optional[str] = Field(default=None, max_length=1000, description="Project summary description")
    owner_id: str = Field(..., description="Clerk ID of project owner")
    status: ProjectStatus = Field(default=ProjectStatus.ACTIVE, description="FSM lifecycle status")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    settings: ProjectSettings = Field(default_factory=ProjectSettings, description="Project configuration settings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata attributes")
    version: int = Field(default=1, description="Optimistic locking revision counter")
    archived_at: Optional[datetime] = Field(default=None, description="Timestamp of archiving")
    deleted_at: Optional[datetime] = Field(default=None, description="Timestamp of soft deletion")
    purge_after: Optional[datetime] = Field(default=None, description="Timestamp after which soft-deleted project is purged")

    class Settings:
        name = "projects"
        indexes = [
            IndexModel(
                [("slug", ASCENDING)],
                unique=True,
                partialFilterExpression={"deleted_at": None, "status": "active"},
                name="idx_projects_slug_unique_active",
            ),
            IndexModel([("owner_id", ASCENDING), ("status", ASCENDING)], name="idx_projects_owner_status"),
            IndexModel([("status", ASCENDING), ("updated_at", DESCENDING)], name="idx_projects_status_updated"),
            IndexModel([("status", ASCENDING), ("purge_after", ASCENDING)], name="idx_projects_purge_retention"),
            IndexModel([("tags", ASCENDING)], name="idx_projects_tags"),
            IndexModel([("name", TEXT), ("description", TEXT)], name="idx_projects_text_search"),
        ]


class ProjectMember(BaseDocument):
    project_id: PydanticObjectId = Field(..., description="Reference to target Project document ID")
    user_id: str = Field(..., description="Clerk user ID of the member")
    role: ProjectRole = Field(default=ProjectRole.MEMBER, description="Assigned role in the project")
    invited_by: Optional[str] = Field(default=None, description="Clerk ID of user who granted membership")
    joined_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Membership join timestamp")

    class Settings:
        name = "project_members"
        indexes = [
            IndexModel([("project_id", ASCENDING), ("user_id", ASCENDING)], unique=True, name="idx_project_member_unique"),
            IndexModel([("user_id", ASCENDING)], name="idx_member_user_id"),
            IndexModel([("project_id", ASCENDING), ("role", ASCENDING)], name="idx_project_role"),
        ]


class ProjectAuditLog(BaseDocument):
    project_id: PydanticObjectId = Field(..., description="Target Project document ID")
    actor_id: str = Field(..., description="Clerk user ID of the actor initiating the action")
    action: ProjectAuditAction = Field(..., description="Action identifier")
    target_user_id: Optional[str] = Field(default=None, description="Clerk user ID of affected member, if applicable")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Snapshot of affected data, diffs, or metadata")

    class Settings:
        name = "project_audit_logs"
        indexes = [
            IndexModel([("project_id", ASCENDING), ("created_at", DESCENDING)], name="idx_audit_project_time"),
            IndexModel([("actor_id", ASCENDING), ("created_at", DESCENDING)], name="idx_audit_actor_time"),
        ]
