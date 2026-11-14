from datetime import datetime
from typing import List, Optional
from beanie import PydanticObjectId
from pymongo import ASCENDING, DESCENDING, IndexModel
from pydantic import BaseModel, Field

from app.core.crypto.envelope import EncryptedEnvelope
from app.db.base import BaseDocument


class ProjectSecret(BaseDocument):
    project_id: PydanticObjectId = Field(..., description="Target Project document ID")
    name: str = Field(..., min_length=1, max_length=128, description="Identifier name (e.g. OPENAI_API_KEY)")
    environment: str = Field(default="production", min_length=1, max_length=50, description="Execution environment")
    description: Optional[str] = Field(default=None, max_length=1000, description="Human-readable description")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    is_system: bool = Field(default=False, description="System-managed flag")

    # Cryptographic Envelope (In-Place, Zero Plaintext)
    envelope: EncryptedEnvelope = Field(..., description="Encrypted secret payload")

    # Metadata, In-Place Rotation & Concurrency
    revision: int = Field(default=1, description="Optimistic locking revision counter (strictly OCC, not history)")
    last_rotated_at: Optional[datetime] = Field(default=None, description="Timestamp of last rotation/replacement")
    expires_at: Optional[datetime] = Field(default=None, description="Optional secret expiration timestamp")
    is_deleted: bool = Field(default=False, description="Soft-delete flag")
    deleted_at: Optional[datetime] = Field(default=None, description="Timestamp of soft-deletion")
    created_by: str = Field(..., description="Clerk ID of creator")
    updated_by: str = Field(..., description="Clerk ID of last updater")

    class Settings:
        name = "project_secrets"
        indexes = [
            # Compound Unique Index: One active secret per name per environment per project
            IndexModel(
                [("project_id", ASCENDING), ("environment", ASCENDING), ("name", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_project_secrets_unique_active",
            ),
            # Query & Listing Indexes
            IndexModel([("project_id", ASCENDING), ("environment", ASCENDING)], name="idx_secrets_project_env"),
            IndexModel([("project_id", ASCENDING), ("is_deleted", ASCENDING), ("updated_at", DESCENDING)], name="idx_secrets_project_listing"),
            IndexModel([("project_id", ASCENDING), ("tags", ASCENDING)], name="idx_secrets_tags"),
            IndexModel([("expires_at", ASCENDING)], name="idx_secrets_expiration"),
        ]
