from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.models.secret import ProjectSecret


class SecretCreateRequest(BaseModel):
    name: str = Field(..., pattern=r"^[A-Z0-9_]{1,128}$", description="Uppercase identifier (e.g. OPENAI_API_KEY)")
    value: SecretStr = Field(..., min_length=1, max_length=65536, description="Plaintext secret value")
    environment: str = Field(default="production", min_length=1, max_length=50, description="Target environment")
    description: Optional[str] = Field(default=None, max_length=1000, description="Description")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    expires_at: Optional[datetime] = Field(default=None, description="Optional expiration date")


class SecretUpdateRequest(BaseModel):
    value: Optional[SecretStr] = Field(default=None, min_length=1, max_length=65536, description="New secret value if replacing")
    description: Optional[str] = Field(default=None, max_length=1000, description="Updated description")
    tags: Optional[List[str]] = Field(default=None, description="Updated tags")
    expires_at: Optional[datetime] = Field(default=None, description="Updated expiration date")
    revision: int = Field(..., description="Current OCC revision counter for concurrency check")


class SecretRotateRequest(BaseModel):
    new_value: SecretStr = Field(..., min_length=1, max_length=65536, description="Rotated plaintext value")
    revision: int = Field(..., description="Current OCC revision counter for concurrency check")


class SecretRevealRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500, description="Operator justification for revealing secret")


class SecretSummaryResponse(BaseModel):
    """Metadata summary response for listings - ZERO PLAINTEXT."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    name: str
    environment: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    is_system: bool = False
    revision: int = Field(..., description="OCC revision counter")
    last_rotated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    @field_validator("id", "project_id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class SecretResponse(SecretSummaryResponse):
    """Detailed metadata response - ZERO PLAINTEXT."""
    algorithm: str
    kek_id: str
    created_by: str
    updated_by: str

    @classmethod
    def from_model(cls, secret: ProjectSecret) -> "SecretResponse":
        return cls(
            id=str(secret.id),
            project_id=str(secret.project_id),
            name=secret.name,
            environment=secret.environment,
            description=secret.description,
            tags=secret.tags,
            is_system=secret.is_system,
            revision=secret.revision,
            last_rotated_at=secret.last_rotated_at,
            expires_at=secret.expires_at,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            algorithm=secret.envelope.algorithm,
            kek_id=secret.envelope.kek_id,
            created_by=secret.created_by,
            updated_by=secret.updated_by,
        )


class SecretValueResponse(BaseModel):
    """Privileged plaintext reveal response."""
    id: str
    name: str
    environment: str
    value: str = Field(..., description="Decrypted plaintext value")
    revealed_at: datetime = Field(..., description="UTC timestamp of reveal")
    audit_logged: bool = Field(default=True, description="Confirmation of audit logging")

    @field_validator("id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class SecretBatchResolveRequest(BaseModel):
    names: List[str] = Field(..., min_length=1, max_length=100, description="List of secret keys to resolve")
    environment: str = Field(default="production", description="Execution environment")
    execution_id: Optional[str] = Field(default=None, description="Associated execution run ID for audit")


class SecretBatchResolveResponse(BaseModel):
    resolved: Dict[str, str] = Field(..., description="Map of secret names to decrypted plaintext values")
    missing: List[str] = Field(default_factory=list, description="Requested keys not found or inactive")
