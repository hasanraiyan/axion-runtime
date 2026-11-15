"""End-user anchor (SRS-07 Section 5.9, FR-70). Asserted by a trusted project backend."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class EndUserStatus(str, Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    DELETED = "deleted"


class ProjectEndUser(BaseDocument):
    project_id: PydanticObjectId
    external_id: str = Field(..., min_length=1, max_length=255)
    display_name: Optional[str] = Field(default=None, max_length=200)
    email: Optional[str] = Field(default=None, max_length=320, description="Label only; never used for authorization")
    attributes: Dict[str, str] = Field(default_factory=dict)
    status: EndUserStatus = EndUserStatus.ACTIVE
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revision: int = 1

    class Settings:
        name = "project_end_users"
        indexes = [
            IndexModel(
                [("project_id", ASCENDING), ("external_id", ASCENDING)],
                unique=True,
                name="idx_project_end_users_unique_external",
            ),
            IndexModel([("project_id", ASCENDING), ("status", ASCENDING)], name="idx_project_end_users_status"),
        ]
