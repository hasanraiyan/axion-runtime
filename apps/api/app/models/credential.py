from datetime import datetime
from enum import Enum
from typing import List, Optional
from beanie import PydanticObjectId
from pymongo import ASCENDING, DESCENDING, IndexModel
from pydantic import Field

from app.db.base import BaseDocument


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ProjectCredential(BaseDocument):
    """
    MongoDB document representing a project-scoped machine API key.
    Stored in the 'project_credentials' collection.
    """
    project_id: PydanticObjectId = Field(
        ...,
        description="Target Project document ID",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Descriptive identifier for this credential (e.g. 'CI/CD Deploy Runner')",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable notes",
    )
    environment: str = Field(
        default="production",
        description="Target environment: 'production', 'staging', 'development', or 'test'",
    )

    # Cryptographic Identity & Display (Zero-Plaintext Storage)
    key_prefix: str = Field(
        ...,
        description="Prefix identifier (e.g. 'axion_live_' or 'axion_test_')",
    )
    masked_key: str = Field(
        ...,
        description="Masked hint for UI display (e.g. 'axion_live_a1b2...9f8e')",
    )
    key_hash: str = Field(
        ...,
        description="SHA-256 cryptographic hash of raw key (hex string)",
    )

    # Permissions & Capabilities (Explicit, non-empty)
    scopes: List[str] = Field(
        ...,
        min_length=1,
        description="Explicit capability scopes (e.g. ['projects:read', 'runs:write'])",
    )
    rate_limit_rpm: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Optional per-minute rate limit override for this credential",
    )

    # Lifecycle & Concurrency
    status: CredentialStatus = Field(
        default=CredentialStatus.ACTIVE,
        description="Lifecycle status: active, revoked, expired",
    )
    revision: int = Field(
        default=1,
        description="Optimistic Concurrency Control (OCC) counter",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Optional expiration timestamp",
    )
    revoked_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when revoked",
    )
    revoked_by: Optional[str] = Field(
        default=None,
        description="Clerk user ID that initiated revocation",
    )

    # Access Telemetry (Debounced writes with preserved total_uses)
    last_used_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp of most recent authenticated request",
    )
    last_used_ip: Optional[str] = Field(
        default=None,
        description="Client IP address of most recent request",
    )
    total_uses: int = Field(
        default=0,
        description="Accurate counter of authenticated invocations",
    )

    # Soft Delete Governance
    is_deleted: bool = Field(
        default=False,
        description="Soft-delete flag",
    )
    deleted_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp of soft-deletion",
    )
    created_by: str = Field(
        ...,
        description="Clerk ID of human creator",
    )
    updated_by: str = Field(
        ...,
        description="Clerk ID of last updater",
    )

    class Settings:
        name = "project_credentials"
        indexes = [
            # 1. Unique index on key_hash for sub-millisecond authentication lookup
            IndexModel(
                [("key_hash", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_credentials_key_hash_unique",
            ),
            # 2. Compound Unique Index: Enforce unique credential name per project among active keys
            IndexModel(
                [("project_id", ASCENDING), ("name", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False, "status": "active"},
                name="idx_credentials_project_name_unique",
            ),
            # 3. Listing & Filtering queries
            IndexModel(
                [("project_id", ASCENDING), ("is_deleted", ASCENDING), ("status", ASCENDING)],
                name="idx_credentials_project_status",
            ),
            IndexModel(
                [("project_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_credentials_project_created",
            ),
            # 4. Expiration sweeper index
            IndexModel(
                [("status", ASCENDING), ("expires_at", ASCENDING)],
                partialFilterExpression={"expires_at": {"$ne": None}, "status": "active"},
                name="idx_credentials_active_expiration",
            ),
        ]
