from datetime import datetime, timezone
from beanie import Document, Insert, Replace, SaveChanges, before_event
from pydantic import Field


class BaseDocument(Document):
    """
    Abstract root document for MongoDB collections using Beanie ODM.
    Provides automatic UTC created_at and updated_at tracking.
    """

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC last update timestamp",
    )

    @before_event(Insert)
    def set_creation_timestamp(self) -> None:
        now = datetime.now(timezone.utc)
        self.created_at = now
        self.updated_at = now

    @before_event([Replace, SaveChanges])
    def update_timestamp(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    class Settings:
        is_root = True
