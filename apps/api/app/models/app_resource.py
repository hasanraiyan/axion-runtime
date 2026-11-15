"""
MCP App resource (SRS-07 Section 5.4, FR-45, FR-46): a cached, hash-pinned copy of an MCP App's HTML.

HTML from a third-party server is untrusted code. It is stored with its SHA-256, never rendered until an
admin approves *that exact hash* together with the specific domains and browser permissions it may use, and
blocked again if the server changes it.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument

CSP_CATEGORIES = ("connectDomains", "resourceDomains", "frameDomains", "baseUriDomains")
PERMISSIONS = ("camera", "microphone", "geolocation", "clipboardWrite")


class AppSyncState(str, Enum):
    IN_SYNC = "in_sync"
    CHANGED = "changed"
    UNAVAILABLE = "unavailable"


class AppResource(BaseDocument):
    project_id: PydanticObjectId
    integration_id: PydanticObjectId
    uri: str = Field(..., max_length=2000)
    mime_type: Optional[str] = None
    content: str = Field(default="", description="Fetched HTML (size-capped); never served unless approved")
    content_hash: str = ""
    size_bytes: int = 0
    declared_csp: Dict[str, List[str]] = Field(default_factory=dict)
    declared_permissions: List[str] = Field(default_factory=list)
    approved_hash: Optional[str] = None
    approved_csp: Dict[str, List[str]] = Field(default_factory=dict)
    approved_permissions: List[str] = Field(default_factory=list)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    sync_state: AppSyncState = AppSyncState.IN_SYNC
    status_message: Optional[str] = Field(default=None, max_length=300)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revision: int = 1

    @property
    def is_approved(self) -> bool:
        """Renderable only when the *current* content hash is the approved one and the server still serves it."""
        return (
            self.sync_state == AppSyncState.IN_SYNC
            and self.approved_hash is not None
            and self.approved_hash == self.content_hash
        )

    class Settings:
        name = "project_app_resources"
        indexes = [
            IndexModel(
                [("integration_id", ASCENDING), ("uri", ASCENDING)], unique=True, name="idx_project_app_resources_unique_uri"
            ),
            IndexModel([("project_id", ASCENDING)], name="idx_project_app_resources_project"),
        ]
