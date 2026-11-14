"""
User Repository providing data access for User documents.
"""
from typing import Optional
from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """
    Repository encapsulating all database interactions for User documents in MongoDB.
    """

    def __init__(self) -> None:
        super().__init__(User)

    async def get_by_clerk_id(self, clerk_id: str) -> Optional[User]:
        """Retrieve a user document by Clerk user ID."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"clerk_id": clerk_id})

    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user document by email address."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"email": email})

    async def count_all(self) -> int:
        """Count total user documents in collection."""
        if not self.is_db_ready():
            return 0
        return await self.count()


def get_user_repository() -> UserRepository:
    """FastAPI dependency provider for UserRepository."""
    return UserRepository()
