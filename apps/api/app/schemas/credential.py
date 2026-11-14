from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.credential import CredentialStatus, ProjectCredential


class CredentialCreateRequest(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Unique display name for the credential",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable notes",
    )
    environment: str = Field(
        default="production",
        pattern="^(production|test|staging|development)$",
        description="Target tier ('production' uses 'axion_live_', others use 'axion_test_')",
    )
    scopes: List[str] = Field(
        ...,
        min_length=1,
        description="Explicit list of capability scopes (e.g. ['projects:read', 'runs:write'])",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Optional expiration timestamp (must be in the future)",
    )
    rate_limit_rpm: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Custom requests-per-minute rate limit",
    )


class CredentialRevokeRequest(BaseModel):
    expected_revision: int = Field(
        ...,
        description="Expected OCC revision counter",
    )
    reason: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional reason for revocation",
    )


class CredentialResponse(BaseModel):
    """Metadata response (Never includes raw_key)."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Credential unique identifier")
    project_id: str = Field(..., description="Associated project ID")
    name: str = Field(..., description="Display name")
    description: Optional[str] = Field(default=None, description="Human-readable notes")
    environment: str = Field(..., description="Environment tier")
    key_prefix: str = Field(..., description="Key prefix (e.g. 'axion_live_')")
    masked_key: str = Field(..., description="Masked preview hint")
    status: CredentialStatus = Field(..., description="Lifecycle status")
    scopes: List[str] = Field(..., description="Granted scopes")
    rate_limit_rpm: Optional[int] = Field(default=None, description="Requests-per-minute limit")
    revision: int = Field(..., description="OCC revision counter")
    expires_at: Optional[datetime] = Field(default=None, description="Expiration timestamp")
    revoked_at: Optional[datetime] = Field(default=None, description="Revocation timestamp")
    last_used_at: Optional[datetime] = Field(default=None, description="Most recent request timestamp")
    total_uses: int = Field(default=0, description="Accurate invocation count")
    created_by: str = Field(..., description="Creator user ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    @field_validator("id", "project_id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v

    @classmethod
    def from_model(cls, cred: ProjectCredential) -> "CredentialResponse":
        return cls(
            id=str(cred.id),
            project_id=str(cred.project_id),
            name=cred.name,
            description=cred.description,
            environment=cred.environment,
            key_prefix=cred.key_prefix,
            masked_key=cred.masked_key,
            status=cred.status,
            scopes=cred.scopes,
            rate_limit_rpm=cred.rate_limit_rpm,
            revision=cred.revision,
            expires_at=cred.expires_at,
            revoked_at=cred.revoked_at,
            last_used_at=cred.last_used_at,
            total_uses=cred.total_uses,
            created_by=cred.created_by,
            created_at=cred.created_at,
            updated_at=cred.updated_at,
        )


class CredentialCreateResponse(CredentialResponse):
    """
    Returned ONLY upon initial creation.
    raw_key is presented strictly once and cannot be retrieved again.
    """
    raw_key: str = Field(
        ...,
        description="Plaintext API key. Store securely; this cannot be retrieved again.",
    )


class CredentialListResponse(BaseModel):
    """List response envelope for credentials metadata."""
    items: List[CredentialResponse] = Field(default_factory=list, description="Credential records")
    total: int = Field(default=0, description="Total matching records count")
    page: Optional[int] = Field(default=None, description="Current page number")
    page_size: Optional[int] = Field(default=None, description="Page size limit")


# Canonical aliases matching both spec and convention
CredentialCreate = CredentialCreateRequest
CredentialRevoke = CredentialRevokeRequest
RevokeRequest = CredentialRevokeRequest
