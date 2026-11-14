from datetime import datetime
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.project import ProjectRole, ProjectSettings, ProjectStatus


class ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, examples=["Core Platform Services"])
    slug: Optional[str] = Field(None, min_length=2, max_length=100, examples=["core-platform-services"])
    description: Optional[str] = Field(None, max_length=1000, examples=["Primary orchestration workspace"])
    tags: List[str] = Field(default_factory=list, examples=[["infrastructure", "prod"]])
    settings: Optional[ProjectSettings] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            if not re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", v):
                raise ValueError("Slug must be lowercase alphanumeric characters and single hyphens")
        return v


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = None
    settings: Optional[ProjectSettings] = None
    metadata: Optional[Dict[str, Any]] = None
    version: int = Field(..., description="Expected current version for optimistic locking", examples=[1])


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    description: Optional[str] = None
    owner_id: str
    status: ProjectStatus
    tags: List[str] = Field(default_factory=list)
    settings: ProjectSettings
    metadata: Dict[str, Any] = Field(default_factory=dict)
    version: int
    user_role: Optional[ProjectRole] = None
    member_count: int = 1
    created_at: datetime
    updated_at: datetime
    archived_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    purge_after: Optional[datetime] = None

    @field_validator("id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class ProjectSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    description: Optional[str] = None
    owner_id: str
    status: ProjectStatus
    tags: List[str] = Field(default_factory=list)
    user_role: ProjectRole
    member_count: int
    created_at: datetime
    updated_at: datetime

    @field_validator("id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class AddMemberRequest(BaseModel):
    user_id: str = Field(..., description="Clerk ID of the user to add", examples=["user_2abc123"])
    role: ProjectRole = Field(default=ProjectRole.MEMBER, description="Initial role", examples=[ProjectRole.MEMBER])

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: ProjectRole) -> ProjectRole:
        if v == ProjectRole.OWNER:
            raise ValueError("Direct assignment of OWNER is prohibited. Use ownership transfer.")
        return v


class UpdateMemberRoleRequest(BaseModel):
    role: ProjectRole = Field(..., description="New role for member", examples=[ProjectRole.ADMIN])

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: ProjectRole) -> ProjectRole:
        if v == ProjectRole.OWNER:
            raise ValueError("Direct upgrade to OWNER is prohibited. Use ownership transfer.")
        return v


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    user_id: str
    role: ProjectRole
    invited_by: Optional[str] = None
    joined_at: datetime
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @field_validator("id", "project_id", mode="before")
    @classmethod
    def convert_ids(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class TransferOwnershipRequest(BaseModel):
    new_owner_user_id: str = Field(..., description="Clerk ID of active member receiving ownership", examples=["user_3def456"])
    former_owner_role: ProjectRole = Field(default=ProjectRole.ADMIN, description="Role assigned to former owner")

    @field_validator("former_owner_role")
    @classmethod
    def validate_former_role(cls, v: ProjectRole) -> ProjectRole:
        if v == ProjectRole.OWNER:
            raise ValueError("Former owner role cannot remain OWNER.")
        return v


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    actor_id: str
    action: str
    target_user_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    @field_validator("id", "project_id", mode="before")
    @classmethod
    def convert_ids(cls, v: Any) -> Any:
        return str(v) if v is not None else v
