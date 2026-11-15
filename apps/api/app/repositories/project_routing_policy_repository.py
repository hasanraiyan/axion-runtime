"""
Project Routing Policy Repository providing data access, compound tenant queries,
atomic OCC updates, and deletion operations for ProjectRoutingPolicy documents.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ASCENDING, ReturnDocument

from app.core.exceptions import ConflictError, NotFoundError
from app.core.protocols.repositories import IProjectRoutingPolicyRepository
from app.models.project_routing_policy import ProjectRoutingPolicy
from app.repositories.base import BaseRepository, serialize_for_mongo


class ProjectRoutingPolicyRepository(
    BaseRepository[ProjectRoutingPolicy], IProjectRoutingPolicyRepository
):
    """
    Repository encapsulating all database interactions, OCC updates,
    and lifecycle operations for ProjectRoutingPolicy documents.
    """

    def __init__(self) -> None:
        super().__init__(ProjectRoutingPolicy)

    async def create(
        self,
        document: ProjectRoutingPolicy,
        session: Optional[Any] = None,
    ) -> ProjectRoutingPolicy:
        """Insert a new ProjectRoutingPolicy document."""
        return await super().create(document, session=session)

    async def get_by_id_and_project(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
    ) -> Optional[ProjectRoutingPolicy]:
        """Fetch a policy by primary key ID scoped to project."""
        if not self.is_db_ready():
            return None
        try:
            target_id = self._to_object_id(policy_id)
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        return await self.find_one({"_id": target_id, "project_id": proj_id})

    async def get_by_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        name: str,
    ) -> Optional[ProjectRoutingPolicy]:
        """Fetch a policy by name scoped to project."""
        if not self.is_db_ready():
            return None
        try:
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        return await self.find_one({"project_id": proj_id, "name": name})

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        is_active: Optional[bool] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectRoutingPolicy], int]:
        """List routing policies for a project with optional active filtering and pagination."""
        if not self.is_db_ready():
            return [], 0
        try:
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return [], 0

        query: Dict[str, Any] = {"project_id": proj_id}
        if is_active is not None:
            query["is_active"] = is_active

        total_count = await self.count(query)
        if total_count == 0:
            return [], 0

        items = await self.find_many(
            query,
            skip=skip,
            limit=limit,
            sort=[("name", ASCENDING)],
        )
        return items, total_count

    async def update_with_revision(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectRoutingPolicy:
        """
        Atomically update routing policy enforcing OCC revision.
        """
        target_id = self._to_object_id(policy_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        # Convert any ObjectId fields in update_dict (like fallback_model_ids or primary_model_id)
        cleaned_dict = dict(update_dict)
        if "primary_model_id" in cleaned_dict:
            cleaned_dict["primary_model_id"] = self._to_object_id(cleaned_dict["primary_model_id"])
        if "fallback_model_ids" in cleaned_dict and isinstance(cleaned_dict["fallback_model_ids"], list):
            cleaned_dict["fallback_model_ids"] = [
                self._to_object_id(fid) for fid in cleaned_dict["fallback_model_ids"]
            ]

        set_fields: Dict[str, Any] = {
            **cleaned_dict,
            "revision": expected_revision + 1,
            "updated_at": now,
        }

        serialized_set_fields = serialize_for_mongo(set_fields)

        query = {
            "_id": target_id,
            "project_id": proj_id,
            "revision": expected_revision,
        }

        col = self.get_collection()
        res = await col.find_one_and_update(
            query,
            {"$set": serialized_set_fields},
            return_document=ReturnDocument.AFTER,
            session=session,
        )

        if res is None:
            existing = await self.get_by_id_and_project(policy_id, project_id)
            if not existing:
                raise NotFoundError(f"Routing policy '{policy_id}' not found")
            if existing.revision != expected_revision:
                raise ConflictError(
                    f"Routing policy '{policy_id}' revision conflict (expected {expected_revision}, current {existing.revision})"
                )
            raise ConflictError("Routing policy update conflict: concurrent modification detected")

        if isinstance(res, ProjectRoutingPolicy):
            return res
        return self.model_class.model_validate(res)

    async def delete(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Delete a routing policy document from MongoDB."""
        target_id = self._to_object_id(policy_id)
        proj_id = self._to_object_id(project_id)

        col = self.get_collection()
        res = await col.delete_one({"_id": target_id, "project_id": proj_id}, session=session)
        return res.deleted_count > 0

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all routing policies for a project during purge."""
        proj_id = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": proj_id}, session=session)
        return res.deleted_count


def get_project_routing_policy_repository() -> ProjectRoutingPolicyRepository:
    """Dependency provider for ProjectRoutingPolicyRepository."""
    return ProjectRoutingPolicyRepository()


__all__ = [
    "ProjectRoutingPolicyRepository",
    "get_project_routing_policy_repository",
    "FakeProjectRoutingPolicyRepository",
]

# Re-export fake for backward-compatibility with tests importing from repository
try:
    from tests.fakes.fake_project_routing_policy_repository import FakeProjectRoutingPolicyRepository
except ImportError:
    pass
