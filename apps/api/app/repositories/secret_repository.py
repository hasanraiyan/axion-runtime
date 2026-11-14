"""
Project Secret Repository providing data access, compound tenant queries,
and atomic OCC updates for ProjectSecret documents.
"""
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import ConflictError, NotFoundError
from app.models.secret import ProjectSecret
from app.repositories.base import BaseRepository, serialize_for_mongo


class ProjectSecretRepository(BaseRepository[ProjectSecret]):
    """
    Repository encapsulating all database interactions, compound tenant queries,
    atomic OCC updates, and soft-delete/purge operations for ProjectSecret documents.
    """

    def __init__(self) -> None:
        super().__init__(ProjectSecret)

    async def create(self, document: ProjectSecret, session: Optional[Any] = None) -> ProjectSecret:
        """
        Insert a new ProjectSecret document. A concurrent create can pass the
        service-level existence check and still hit the unique compound index,
        so translate that DuplicateKeyError into a proper 409 Conflict instead
        of letting it surface as a 500.
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            key_pattern = (exc.details or {}).get("keyPattern", {})
            if not key_pattern or {"project_id", "environment", "name"} <= set(key_pattern):
                raise ConflictError(
                    f"Secret '{document.name}' already exists in environment '{document.environment}'"
                ) from exc
            fields = ", ".join(key_pattern)
            raise ConflictError(f"Secret violates a unique constraint on: {fields}") from exc

    async def check_exists(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: str,
        name: str,
    ) -> bool:
        """Check whether an active secret with the given name exists in the environment."""
        if not self.is_db_ready():
            return False
        return await self.exists(
            {
                "project_id": self._to_object_id(project_id),
                "environment": environment,
                "name": name,
                "is_deleted": False,
            }
        )

    async def get_by_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: str,
        name: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectSecret]:
        """Fetch a secret document by project ID, environment, and name."""
        if not self.is_db_ready():
            return None
        query: Dict[str, Any] = {
            "project_id": self._to_object_id(project_id),
            "environment": environment,
            "name": name,
        }
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def get_by_id_and_project(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectSecret]:
        """Fetch a secret by its primary key ID ensuring project tenant scoping."""
        if not self.is_db_ready():
            return None
        try:
            target_id = self._to_object_id(secret_id)
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        query: Dict[str, Any] = {
            "_id": target_id,
            "project_id": proj_id,
        }
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectSecret], int]:
        """
        List secrets for a project with optional filtering, search, sorting, and pagination.
        Returns a tuple of (secrets, total_count).
        """
        if not self.is_db_ready():
            return [], 0

        query: Dict[str, Any] = {
            "project_id": self._to_object_id(project_id),
        }
        if not include_deleted:
            query["is_deleted"] = False

        if environment:
            query["environment"] = environment

        if tags:
            query["tags"] = {"$in": tags}

        if search:
            escaped_search = re.escape(search)
            query["$or"] = [
                {"name": {"$regex": escaped_search, "$options": "i"}},
                {"description": {"$regex": escaped_search, "$options": "i"}},
            ]

        # Sorting validation
        allowed_sorts = {
            "name": "name",
            "created_at": "created_at",
            "updated_at": "updated_at",
            "revision": "revision",
            "last_rotated_at": "last_rotated_at",
            "expires_at": "expires_at",
        }
        sort_field = allowed_sorts.get(sort_by, "updated_at")
        sort_direction = DESCENDING if sort_order.lower() == "desc" else ASCENDING

        total = await self.count(query)
        items = await self.find_many(
            query,
            skip=skip,
            limit=limit,
            sort=[(sort_field, sort_direction)],
        )
        return items, total

    async def find_by_names(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: str,
        names: List[str],
        include_deleted: bool = False,
    ) -> List[ProjectSecret]:
        """Batch query secrets matching an environment and list of names ($in)."""
        if not self.is_db_ready() or not names:
            return []

        query: Dict[str, Any] = {
            "project_id": self._to_object_id(project_id),
            "environment": environment,
            "name": {"$in": names},
        }
        if not include_deleted:
            query["is_deleted"] = False

        return await self.find_many(query, limit=len(names))

    async def update_with_revision(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectSecret:
        """
        Atomically update secret document enforcing expected revision for OCC.
        Increments revision counter and sets updated_at.
        Raises ConflictError if revision does not match.
        """
        target_id = self._to_object_id(secret_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        set_fields: Dict[str, Any] = {
            **update_dict,
            "revision": expected_revision + 1,
            "updated_at": now,
        }

        # Convert nested Pydantic submodels (like EncryptedEnvelope) to dicts for PyMongo
        serialized_set_fields = serialize_for_mongo(set_fields)

        query = {
            "_id": target_id,
            "project_id": proj_id,
            "revision": expected_revision,
            "is_deleted": False,
        }

        col = self.get_collection()
        res = await col.find_one_and_update(
            query,
            {"$set": serialized_set_fields},
            return_document=ReturnDocument.AFTER,
            session=session,
        )

        if res is None:
            existing = await self.get_by_id_and_project(secret_id, project_id, include_deleted=True)
            if not existing:
                raise NotFoundError(f"Secret '{secret_id}' not found")
            if existing.is_deleted:
                raise ConflictError(f"Secret '{secret_id}' has been deleted")
            if existing.revision != expected_revision:
                raise ConflictError("Secret has been modified by another process. Please reload and retry.")
            raise ConflictError("Secret update conflict: document was modified by another concurrent request")

        if isinstance(res, ProjectSecret):
            return res
        return self.model_class.model_validate(res)

    async def soft_delete(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Soft-delete a secret document by setting is_deleted=True and deleted_at."""
        target_id = self._to_object_id(secret_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        col = self.get_collection()
        res = await col.find_one_and_update(
            {"_id": target_id, "project_id": proj_id, "is_deleted": False},
            {"$set": {"is_deleted": True, "deleted_at": now, "updated_at": now}},
            session=session,
        )
        return res is not None

    async def purge(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Permanently delete a secret document from the collection."""
        target_id = self._to_object_id(secret_id)
        proj_id = self._to_object_id(project_id)

        col = self.get_collection()
        res = await col.delete_one(
            {"_id": target_id, "project_id": proj_id},
            session=session,
        )
        return res.deleted_count > 0

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all secrets belonging to a project."""
        proj_id = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": proj_id}, session=session)
        return res.deleted_count


def get_secret_repository() -> ProjectSecretRepository:
    """Dependency provider for ProjectSecretRepository."""
    return ProjectSecretRepository()
