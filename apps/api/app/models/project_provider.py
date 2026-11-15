from datetime import datetime
from enum import Enum
from typing import Dict, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class ProviderType(str, Enum):
    """Supported provider architectures and integrations (SRS-06 Section 3 & 4.1)."""

    GOOGLE_GENAI = "google_genai"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM_OPENAI_COMPATIBLE = "custom_openai_compatible"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    MISTRAL = "mistral"
    COHERE = "cohere"


class ProviderStatus(str, Enum):
    """Provider operational status (SRS-06 Section 4.1 & 7)."""

    ACTIVE = "active"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    ERROR = "error"


class HealthcheckStatus(str, Enum):
    """Healthcheck connectivity outcome (SRS-06 Section 4.1 & 5 FR-03)."""

    HEALTHY = "healthy"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"


class ProjectProvider(BaseDocument):
    """
    Project Provider document representing upstream LLM / inference provider connectivity.
    Strictly zero plaintext credentials; references project_secrets by secret_id (MOD-02).
    """

    project_id: PydanticObjectId = Field(
        ..., description="Foreign key binding the provider strictly to an Axion Project"
    )
    name: str = Field(
        ..., min_length=1, max_length=100, description="Human-readable name (e.g., 'Corporate DeepSeek Instance')"
    )
    slug: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        description="Unique URL-safe identifier within the project",
    )
    provider_type: ProviderType = Field(
        ..., description="Supported provider architecture"
    )
    secret_id: PydanticObjectId = Field(
        ..., description="Foreign key to project_secrets (MOD-02) containing encrypted credentials"
    )
    base_url: Optional[str] = Field(
        default=None, description="Upstream API endpoint URL (mandatory for custom providers)"
    )
    api_version: Optional[str] = Field(
        default=None, max_length=50, description="Provider API version parameter"
    )
    custom_headers: Dict[str, str] = Field(
        default_factory=dict, description="Arbitrary key-value string pairs injected into outgoing HTTP calls"
    )
    timeout_seconds: int = Field(
        default=60, ge=1, le=600, description="Maximum socket and read timeout for upstream requests"
    )
    max_retries: int = Field(
        default=2, ge=0, le=5, description="Automatic retry attempts on transient network or 5xx failures"
    )
    status: ProviderStatus = Field(
        default=ProviderStatus.ACTIVE, description="Operational status of the provider"
    )
    last_healthcheck_at: Optional[datetime] = Field(
        default=None, description="Timestamp of the most recent automated or manual connectivity test"
    )
    healthcheck_status: Optional[HealthcheckStatus] = Field(
        default=None, description="Outcome of last healthcheck test"
    )
    healthcheck_latency_ms: Optional[int] = Field(
        default=None, ge=0, description="Latency in milliseconds of the last successful healthcheck"
    )
    healthcheck_message: Optional[str] = Field(
        default=None, max_length=500, description="Descriptive message or error reason from last healthcheck"
    )
    is_default: bool = Field(
        default=False, description="Indicates whether this is the default provider for the project"
    )
    is_deleted: bool = Field(
        default=False, description="Soft-delete status indicator"
    )
    deleted_at: Optional[datetime] = Field(
        default=None, description="Soft-deletion timestamp"
    )
    revision: int = Field(
        default=1, description="Optimistic Concurrency Control (OCC) revision counter"
    )
    created_by: str = Field(
        ..., description="Clerk user ID or machine credential ID that created the provider"
    )
    updated_by: str = Field(
        ..., description="Clerk user ID or machine credential ID of last modification"
    )

    class Settings:
        name = "project_providers"
        indexes = [
            # Compound Unique Index: Enforces unique slug per project (excluding deleted)
            IndexModel(
                [("project_id", ASCENDING), ("slug", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_project_providers_unique_slug",
            ),
            # Compound Unique Index: Prevents duplicate provider names per project (excluding deleted)
            IndexModel(
                [("project_id", ASCENDING), ("name", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_project_providers_unique_name",
            ),
            # Query Filter Index: Accelerates listing active providers
            IndexModel(
                [("project_id", ASCENDING), ("is_deleted", ASCENDING), ("status", ASCENDING)],
                name="idx_project_providers_project_deleted_status",
            ),
            # Secret Reference Index: Supports cascade validation before secret deletion
            IndexModel(
                [("secret_id", ASCENDING)],
                name="idx_project_providers_secret_id",
            ),
        ]
