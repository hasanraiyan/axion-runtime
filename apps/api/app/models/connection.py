"""
Connection models (SRS-07 Sections 5.3, 5.10, 5.11): credentials owned by one *subject*, hosted
connect sessions, per-integration OAuth client registration, and per-project tool policy.

Credentials are stored only as MOD-02 envelopes whose AAD binds ``(project, integration, subject)``,
so ciphertext cannot be replayed under another subject, integration, or project.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.core.crypto.envelope import EncryptedEnvelope
from app.db.base import BaseDocument
from app.models.tool import ApprovalPolicy


class ConnectionSubjectType(str, Enum):
    PROJECT = "project"
    MEMBER = "member"
    END_USER = "end_user"


class CredentialKind(str, Enum):
    OAUTH = "oauth"
    API_KEY = "api_key"
    BEARER = "bearer"


class ConnectionStatus(str, Enum):
    ACTIVE = "active"
    NEEDS_AUTH = "needs_auth"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class IntegrationConnection(BaseDocument):
    project_id: PydanticObjectId
    integration_id: PydanticObjectId
    subject_type: ConnectionSubjectType
    subject_id: Optional[str] = Field(default=None, description="Clerk id (member), end-user id, or null (project)")
    subject_key: str = Field(..., description="project | member:{id} | end_user:{id}")
    credential_kind: CredentialKind
    access_envelope: EncryptedEnvelope
    refresh_envelope: Optional[EncryptedEnvelope] = None
    expires_at: Optional[datetime] = None
    granted_scopes: List[str] = Field(default_factory=list)
    external_account: Dict[str, Any] = Field(default_factory=dict, description="Non-sensitive label, e.g. {'label': 'ann@x.com'}")
    status: ConnectionStatus = ConnectionStatus.ACTIVE
    last_used_at: Optional[datetime] = None
    last_error: Optional[str] = Field(default=None, max_length=500)
    last_error_at: Optional[datetime] = None
    revision: int = 1

    class Settings:
        name = "integration_connections"
        indexes = [
            IndexModel(
                [("integration_id", ASCENDING), ("subject_key", ASCENDING)],
                unique=True,
                name="idx_integration_connections_unique_subject",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("subject_type", ASCENDING), ("subject_id", ASCENDING)],
                name="idx_integration_connections_subject",
            ),
            IndexModel([("integration_id", ASCENDING), ("status", ASCENDING)], name="idx_integration_connections_status"),
        ]


class ConnectSessionStatus(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


class ConnectSession(BaseDocument):
    token_hash: str = Field(..., description="SHA-256 of the high-entropy link secret; the secret is never stored")
    project_id: PydanticObjectId
    integration_id: PydanticObjectId
    subject_type: ConnectionSubjectType
    subject_id: Optional[str] = None
    subject_key: str
    created_by: str
    return_url: Optional[str] = None
    state_hash: Optional[str] = Field(default=None, description="SHA-256 of the OAuth state parameter")
    pkce_verifier_envelope: Optional[EncryptedEnvelope] = None
    status: ConnectSessionStatus = ConnectSessionStatus.PENDING
    error: Optional[str] = Field(default=None, max_length=300)
    expires_at: datetime
    consumed_at: Optional[datetime] = None

    class Settings:
        name = "integration_connect_sessions"
        indexes = [
            IndexModel([("token_hash", ASCENDING)], unique=True, name="idx_connect_sessions_token"),
            IndexModel([("state_hash", ASCENDING)], name="idx_connect_sessions_state"),
            # Expired sessions are removed by MongoDB itself.
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="idx_connect_sessions_ttl"),
        ]


class IntegrationOAuthClient(BaseDocument):
    """Discovered endpoints and the OAuth client used for one integration (dynamic or manual)."""

    project_id: PydanticObjectId
    integration_id: PydanticObjectId
    issuer: str
    resource: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: Optional[str] = None
    client_id: str
    client_secret_envelope: Optional[EncryptedEnvelope] = None
    token_endpoint_auth_method: str = "none"
    redirect_uri: str
    dynamically_registered: bool = False
    iss_required: bool = False
    scopes: List[str] = Field(default_factory=list)
    revision: int = 1

    class Settings:
        name = "integration_oauth_clients"
        indexes = [
            IndexModel([("integration_id", ASCENDING)], unique=True, name="idx_integration_oauth_clients_integration"),
        ]


class ProjectToolPolicy(BaseDocument):
    project_id: PydanticObjectId
    allowed_return_origins: List[str] = Field(default_factory=list)
    end_user_connect_enabled: bool = False
    connect_link_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    default_approval_policy: ApprovalPolicy = Field(
        default=ApprovalPolicy.REQUIRE_APPROVAL,
        description="Floor for newly discovered tools that are not provably read-only: require_approval or deny",
    )
    invocation_content_retention_days: int = Field(
        default=0, ge=0, le=365, description="0 stores metadata only; N>0 also keeps (truncated) results for N days"
    )
    end_user_default_rate_limit_per_minute: Optional[int] = Field(
        default=None, ge=1, description="Per-end-user cap for tools that do not set their own"
    )
    revision: int = 1

    class Settings:
        name = "project_tool_policies"
        indexes = [IndexModel([("project_id", ASCENDING)], unique=True, name="idx_project_tool_policies_project")]
