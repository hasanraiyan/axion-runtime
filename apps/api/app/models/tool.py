"""
Tool models (SRS-07 Sections 5.2 and 5.5).

``ToolDefinition`` is written only by discovery (or manual authoring);
``ToolSetting`` is written only by administrators and is keyed by ``tool_key`` so
settings survive a tool disappearing upstream and returning. ``ToolBinding`` is
Gate 1 (availability and audience).
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from beanie import PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class ToolSyncState(str, Enum):
    IN_SYNC = "in_sync"
    CHANGED = "changed"
    REMOVED_UPSTREAM = "removed_upstream"
    MANUAL = "manual"


class ApprovalPolicy(str, Enum):
    AUTO = "auto"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ToolAnnotations(BaseModel):
    """Behavioural hints (MCP annotations, native manifests, or HTTP method)."""

    read_only: Optional[bool] = None
    destructive: Optional[bool] = None
    idempotent: Optional[bool] = None
    open_world: Optional[bool] = None


class ToolUi(BaseModel):
    resource_uri: Optional[str] = None
    visibility: List[str] = Field(default_factory=lambda: ["model", "app"])
    app_resource_id: Optional[PydanticObjectId] = None


class ToolDefinition(BaseDocument):
    project_id: PydanticObjectId
    integration_id: PydanticObjectId
    tool_key: str = Field(..., min_length=3, max_length=160, description="{integration_slug}.{normalized_name}")
    upstream_name: str = Field(..., min_length=1, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=8000)
    input_schema: Dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    output_schema: Optional[Dict[str, Any]] = None
    annotations: ToolAnnotations = Field(default_factory=ToolAnnotations)
    ui: Optional[ToolUi] = None
    definition_hash: str
    sync_state: ToolSyncState = ToolSyncState.IN_SYNC
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revision: int = 1

    class Settings:
        name = "project_tools"
        indexes = [
            IndexModel(
                [("project_id", ASCENDING), ("tool_key", ASCENDING)],
                unique=True,
                name="idx_project_tools_unique_key",
            ),
            IndexModel(
                [("integration_id", ASCENDING), ("sync_state", ASCENDING)],
                name="idx_project_tools_integration_sync",
            ),
        ]


class ToolSetting(BaseDocument):
    project_id: PydanticObjectId
    tool_key: str = Field(..., min_length=3, max_length=160)
    is_enabled: bool = False
    approved_hash: Optional[str] = None
    approval_policy: ApprovalPolicy = ApprovalPolicy.REQUIRE_APPROVAL
    description_override: Optional[str] = Field(default=None, max_length=8000)
    locked_arguments: Dict[str, Any] = Field(default_factory=dict)
    default_arguments: Dict[str, Any] = Field(default_factory=dict)
    context_arguments: Dict[str, str] = Field(default_factory=dict, description="parameter -> context key (FR-76)")
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=300)
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1)
    per_end_user_rate_limit_per_minute: Optional[int] = Field(default=None, ge=1)
    revision: int = 1
    updated_by: Optional[str] = None

    class Settings:
        name = "project_tool_settings"
        indexes = [
            IndexModel(
                [("project_id", ASCENDING), ("tool_key", ASCENDING)],
                unique=True,
                name="idx_project_tool_settings_unique_key",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("is_enabled", ASCENDING)],
                name="idx_project_tool_settings_enabled",
            ),
        ]


class BindingSubjectType(str, Enum):
    PROJECT_DEFAULT = "project_default"
    AGENT = "agent"
    END_USER = "end_user"


class BindingTargetType(str, Enum):
    INTEGRATION = "integration"
    TOOL = "tool"


class BindingEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Audience(str, Enum):
    MEMBERS = "members"
    END_USERS = "end_users"
    MACHINE = "machine"


class ToolBinding(BaseDocument):
    project_id: PydanticObjectId
    subject_type: BindingSubjectType
    subject_id: Optional[str] = Field(
        default=None, description="Agent id or ProjectEndUser id; null for project default"
    )
    audience: List[Audience] = Field(default_factory=lambda: [Audience.MEMBERS])
    target_type: BindingTargetType
    target_id: str = Field(..., description="Integration id or tool_key")
    effect: BindingEffect = BindingEffect.ALLOW
    approval_policy_override: Optional[ApprovalPolicy] = None
    revision: int = 1
    created_by: Optional[str] = None

    class Settings:
        name = "tool_bindings"
        indexes = [
            IndexModel(
                [
                    ("project_id", ASCENDING),
                    ("subject_type", ASCENDING),
                    ("subject_id", ASCENDING),
                    ("target_type", ASCENDING),
                    ("target_id", ASCENDING),
                ],
                unique=True,
                name="idx_tool_bindings_unique_rule",
            ),
            IndexModel([("project_id", ASCENDING), ("subject_id", ASCENDING)], name="idx_tool_bindings_subject"),
        ]
