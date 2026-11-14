"""
Project Member Repository providing data access for ProjectMember documents.
"""
from typing import Any, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import ConflictError
from app.models.project import ProjectMember
from app.repositories.base import BaseRepository


class ProjectMemberRepository(BaseRepository[ProjectMember]):
    """
    Repository encapsulating all database interactions for ProjectMember documents.
    """

    def __init__(self) -> None:
        super().__init__(ProjectMember)

    async def get_membership(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        user_id: str,
    ) -> Optional[ProjectMember]:
        """Retrieve a specific user's membership in a project."""
        if not self.is_db_ready():
            return None
        pid = self._to_object_id(project_id)
        return await self.find_one({"project_id": pid, "user_id": user_id})

    async def list_project_ids_for_user(self, user_id: str) -> List[PydanticObjectId]:
        """Retrieve all project IDs associated with a specific user."""
        if not self.is_db_ready():
            return []
        members = await self.find_many({"user_id": user_id}, limit=10000)
        return [m.project_id for m in members]

    async def list_members(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        skip: Union[int, Any] = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectMember], int]:
        """
        List members for a given project with pagination.
        Supports both (skip, limit) and pagination_params objects.
        Returns a tuple of (members, total_count).
        """
        if not self.is_db_ready():
            return ([], 0)

        # Handle pagination_params object if passed as first pagination argument
        if not isinstance(skip, int):
            if hasattr(skip, "offset") and hasattr(skip, "limit"):
                actual_skip = getattr(skip, "offset", 0)
                actual_limit = getattr(skip, "limit", 50)
            elif hasattr(skip, "page") and hasattr(skip, "page_size"):
                page = getattr(skip, "page", 1)
                size = getattr(skip, "page_size", 50)
                actual_skip = max(0, (page - 1) * size)
                actual_limit = size
            else:
                actual_skip = 0
                actual_limit = limit
        else:
            actual_skip = skip
            actual_limit = limit

        pid = self._to_object_id(project_id)
        query = {"project_id": pid}

        total = await self.count(query)
        if total == 0:
            return ([], 0)

        items = await self.find_many(query, skip=actual_skip, limit=actual_limit, sort="+joined_at")
        return (items, total)

    async def count_members(self, project_id: Union[PydanticObjectId, ObjectId, str]) -> int:
        """Count total members registered to a project."""
        if not self.is_db_ready():
            return 0
        pid = self._to_object_id(project_id)
        return await self.count({"project_id": pid})

    async def create(self, document: ProjectMember, session: Optional[Any] = None) -> ProjectMember:
        """
        Insert a new ProjectMember document.
        Catches DuplicateKeyError and raises ConflictError.
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            key_pattern = (exc.details or {}).get("keyPattern", {})
            if not key_pattern or {"project_id", "user_id"} <= set(key_pattern):
                raise ConflictError("User is already a member of this project") from exc
            fields = ", ".join(key_pattern)
            raise ConflictError(f"Project member violates a unique constraint on: {fields}") from exc

    async def update(self, document: ProjectMember, session: Optional[Any] = None) -> ProjectMember:
        """Update an existing ProjectMember document."""
        return await super().update(document, session=session)

    async def delete(self, document: ProjectMember, session: Optional[Any] = None) -> None:
        """Delete a ProjectMember document."""
        await super().delete(document, session=session)

    async def delete_by_project_id(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all members of a project (used during project purge)."""
        pid = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": pid}, session=session)
        return res.deleted_count


def get_project_member_repository() -> ProjectMemberRepository:
    """FastAPI dependency provider for ProjectMemberRepository."""
    return ProjectMemberRepository()
