"""
Integration model (SRS-07 Section 5.1).

An Integration is one project's configured connection to a provider of tools
(native provider, MCP server, REST API, or custom endpoint). It holds **no
plaintext credentials**: every secret is a MOD-02 ``secret_id`` reference.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from beanie import PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class IntegrationType(str, Enum):
    NATIVE = "native"
    MCP = "mcp"
    REST = "rest"
    CUSTOM = "custom"


class IntegrationStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEGRADED = "degraded"
    NEEDS_AUTH = "needs_auth"
    ERROR = "error"
    DISABLED = "disabled"


class AuthType(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    BASIC = "basic"
    CUSTOM_HEADERS = "custom_headers"
    OAUTH_AUTHORIZATION_CODE = "oauth_authorization_code"
    OAUTH_CLIENT_CREDENTIALS = "oauth_client_credentials"


class CredentialMode(str, Enum):
    """Who authenticates upstream (SRS-07 Section 4.1)."""

    PROJECT_SHARED = "project_shared"
    PER_USER = "per_user"


class EndUserAccess(str, Enum):
    CLOSED = "closed"
    OPEN = "open"


class AuthProfile(BaseModel):
    """Declarative description of how an integration authenticates (SRS-07 5.1.2)."""

    auth_type: AuthType = Field(default=AuthType.NONE)
    credential_mode: CredentialMode = Field(default=CredentialMode.PROJECT_SHARED)
    secret_id: Optional[PydanticObjectId] = Field(default=None, description="Primary MOD-02 secret reference")
    secondary_secret_id: Optional[PydanticObjectId] = Field(
        default=None, description="Second secret (basic-auth password)"
    )
    placement: Optional[str] = Field(default=None, pattern="^(header|query)$")
    name: Optional[str] = Field(default=None, max_length=100, description="Header or query parameter name")
    prefix: Optional[str] = Field(default=None, max_length=50)
    username: Optional[str] = Field(default=None, max_length=200, description="Basic-auth username (not secret)")
    headers: Dict[str, str] = Field(
        default_factory=dict, description="custom_headers values; may contain {{secrets.NAME}} placeholders"
    )
    oauth: Dict[str, Any] = Field(default_factory=dict, description="Non-secret OAuth settings (scopes, client_id)")

    def same_credentials_as(self, other: "AuthProfile") -> bool:
        """True when existing stored connections would still be valid under ``other`` (SRS-07 5.1.2)."""
        return (
            self.auth_type == other.auth_type
            and self.credential_mode == other.credential_mode
            and self.secret_id == other.secret_id
            and (self.oauth or {}).get("client_id") == (other.oauth or {}).get("client_id")
        )


class SharedIdentityAck(BaseModel):
    acknowledged_by: str
    acknowledged_at: datetime
    text_version: str = "1"


class IntegrationHealth(BaseModel):
    status: Optional[str] = None
    latency_ms: Optional[int] = Field(default=None, ge=0)
    checked_at: Optional[datetime] = None
    message: Optional[str] = Field(default=None, max_length=500)


class Integration(BaseDocument):
    project_id: PydanticObjectId = Field(..., description="Tenant boundary")
    type: IntegrationType = Field(..., description="Immutable integration type")
    slug: str = Field(
        ...,
        pattern=r"^[a-z][a-z0-9_]{1,39}$",
        description="Immutable namespace segment of every tool_key",
    )
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    config: Dict[str, Any] = Field(default_factory=dict, description="Adapter-validated, opaque to services")
    auth_profile: AuthProfile = Field(default_factory=AuthProfile)
    status: IntegrationStatus = Field(default=IntegrationStatus.DRAFT)
    status_reason: Optional[str] = Field(default=None, max_length=500)
    is_enabled: bool = Field(default=True)
    end_user_access: EndUserAccess = Field(default=EndUserAccess.CLOSED)
    shared_identity_ack: Optional[SharedIdentityAck] = None
    last_discovery_at: Optional[datetime] = None
    catalog_hash: Optional[str] = None
    catalog_stale: bool = Field(
        default=False, description="The server announced a change that has not been re-discovered yet (per-user integrations)"
    )
    health: IntegrationHealth = Field(default_factory=IntegrationHealth)
    consecutive_failures: int = Field(default=0, ge=0)
    referenced_secret_ids: List[PydanticObjectId] = Field(
        default_factory=list, description="Derived: every MOD-02 secret this integration references"
    )
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    revision: int = Field(default=1)
    created_by: str
    updated_by: str

    class Settings:
        name = "project_integrations"
        indexes = [
            # Slugs stay reserved while soft-deleted (docs/learnings.md lesson 3): no partial filter.
            IndexModel(
                [("project_id", ASCENDING), ("slug", ASCENDING)],
                unique=True,
                name="idx_project_integrations_unique_slug",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("name", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_project_integrations_unique_name",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("is_deleted", ASCENDING), ("status", ASCENDING)],
                name="idx_project_integrations_project_deleted_status",
            ),
            IndexModel([("project_id", ASCENDING), ("type", ASCENDING)], name="idx_project_integrations_type"),
            IndexModel([("referenced_secret_ids", ASCENDING)], name="idx_project_integrations_secret_refs"),
        ]
