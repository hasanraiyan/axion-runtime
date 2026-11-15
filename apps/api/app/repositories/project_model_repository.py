"""
Project Model Repository providing data access, compound capability queries,
atomic OCC updates, and soft-delete/purge operations for ProjectModel documents.
"""
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import (
    ConflictError,
    DuplicateModelError,
    ModelRevisionConflictError,
    NotFoundError,
)
from app.core.protocols.repositories import IProjectModelRepository
from app.models.project_model import ModelType, ProjectModel
from app.repositories.base import BaseRepository, serialize_for_mongo


def translate_model_duplicate_key(exc: DuplicateKeyError, document: ProjectModel) -> Exception:
    """Translate DuplicateKeyError by inspecting keyPattern."""
    key_pattern = (exc.details or {}).get("keyPattern", {})
    if "model_id" in key_pattern:
        return DuplicateModelError(document.model_id)
    fields = ", ".join(key_pattern.keys()) if key_pattern else "unique index"
    return ConflictError(f"Model violates unique constraint on: {fields}")


class ProjectModelRepository(BaseRepository[ProjectModel], IProjectModelRepository):
    """
    Repository encapsulating all database interactions, compound capability queries,
    atomic OCC updates, and soft-delete/purge operations for ProjectModel documents.
    """

    def __init__(self) -> None:
        super().__init__(ProjectModel)

    async def create(
        self,
        document: ProjectModel,
        session: Optional[Any] = None,
    ) -> ProjectModel:
        """
        Insert a new ProjectModel document. Translates DuplicateKeyError on
        (provider_id, model_id) into a DuplicateModelError.
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            raise translate_model_duplicate_key(exc, document) from exc

    async def get_by_id_and_project(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectModel]:
        """Fetch a model by primary key ID ensuring project boundary scoping."""
        if not self.is_db_ready():
            return None
        try:
            target_id = self._to_object_id(model_id)
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

    async def get_by_provider_and_model_id(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        model_id: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectModel]:
        """Fetch a model by its parent provider ID and upstream model_id."""
        if not self.is_db_ready():
            return None
        try:
            prov_id = self._to_object_id(provider_id)
        except ValueError:
            return None

        query: Dict[str, Any] = {
            "provider_id": prov_id,
            "model_id": model_id,
        }
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        model_type: Optional[ModelType] = None,
        supports_tools: Optional[bool] = None,
        supports_vision: Optional[bool] = None,
        supports_json_mode: Optional[bool] = None,
        is_enabled: Optional[bool] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectModel], int]:
        """
        List models for a project with optional filtering by capability flags,
        model type, provider, search, and pagination.
        Returns a tuple of (models, total_count).
        """
        if not self.is_db_ready():
            return [], 0
        try:
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return [], 0

        query: Dict[str, Any] = {"project_id": proj_id}
        if not include_deleted:
            query["is_deleted"] = False
        if provider_id is not None:
            try:
                query["provider_id"] = self._to_object_id(provider_id)
            except ValueError:
                return [], 0
        if model_type is not None:
            query["model_type"] = model_type.value if isinstance(model_type, ModelType) else model_type
        if supports_tools is not None:
            query["supports_tools"] = supports_tools
        if supports_vision is not None:
            query["supports_vision"] = supports_vision
        if supports_json_mode is not None:
            query["supports_json_mode"] = supports_json_mode
        if is_enabled is not None:
            query["is_enabled"] = is_enabled

        if search:
            escaped_search = re.escape(search.strip())
            regex = {"$regex": escaped_search, "$options": "i"}
            query["$or"] = [{"model_id": regex}, {"display_name": regex}]

        total_count = await self.count(query)
        if total_count == 0:
            return [], 0

        sort_dir = DESCENDING if sort_order.lower() == "desc" else ASCENDING
        valid_sort_fields = {
            "created_at",
            "updated_at",
            "model_id",
            "display_name",
            "input_cost_per_million",
            "output_cost_per_million",
        }
        applied_sort = sort_by if sort_by in valid_sort_fields else "created_at"

        items = await self.find_many(
            query,
            skip=skip,
            limit=limit,
            sort=[(applied_sort, sort_dir)],
        )
        return items, total_count

    async def list_by_provider(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> List[ProjectModel]:
        """List all models registered under a specific provider."""
        if not self.is_db_ready():
            return []
        try:
            prov_id = self._to_object_id(provider_id)
        except ValueError:
            return []

        query: Dict[str, Any] = {"provider_id": prov_id}
        if not include_deleted:
            query["is_deleted"] = False

        return await self.find_many(query, limit=500, sort=[("model_id", ASCENDING)])

    async def update_with_revision(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectModel:
        """
        Atomically update model document enforcing expected revision for OCC.
        Increments revision counter and sets updated_at.
        Raises ModelRevisionConflictError if revision does not match.
        """
        target_id = self._to_object_id(model_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        set_fields: Dict[str, Any] = {
            **update_dict,
            "revision": expected_revision + 1,
            "updated_at": now,
        }

        serialized_set_fields = serialize_for_mongo(set_fields)

        query = {
            "_id": target_id,
            "project_id": proj_id,
            "revision": expected_revision,
            "is_deleted": False,
        }

        col = self.get_collection()
        try:
            res = await col.find_one_and_update(
                query,
                {"$set": serialized_set_fields},
                return_document=ReturnDocument.AFTER,
                session=session,
            )
        except DuplicateKeyError as exc:
            key_pattern = (exc.details or {}).get("keyPattern", {})
            if "model_id" in key_pattern:
                raise DuplicateModelError(str(update_dict.get("model_id", "duplicate"))) from exc
            fields = ", ".join(key_pattern.keys()) if key_pattern else "unique index"
            raise ConflictError(f"Model violates unique constraint on: {fields}") from exc

        if res is None:
            existing = await self.get_by_id_and_project(model_id, project_id, include_deleted=True)
            if not existing:
                raise NotFoundError(f"Model '{model_id}' not found")
            if existing.is_deleted:
                raise ConflictError(f"Model '{model_id}' has been deleted")
            if existing.revision != expected_revision:
                raise ModelRevisionConflictError(
                    f"Model '{model_id}' revision conflict (expected {expected_revision}, current {existing.revision})"
                )
            raise ConflictError("Model update conflict: concurrent modification detected")

        if isinstance(res, ProjectModel):
            return res
        return self.model_class.model_validate(res)

    async def unset_other_defaults(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        model_type: ModelType,
        exclude_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        session: Optional[Any] = None,
    ) -> int:
        """
        Atomically clear is_default on other active models of the same model_type within the project.
        """
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)
        type_val = model_type.value if isinstance(model_type, ModelType) else model_type
        query: Dict[str, Any] = {
            "project_id": proj_id,
            "model_type": type_val,
            "is_default": True,
            "is_deleted": False,
        }
        if exclude_id is not None:
            query["_id"] = {"$ne": self._to_object_id(exclude_id)}

        col = self.get_collection()
        res = await col.update_many(
            query,
            {"$set": {"is_default": False, "updated_at": now}},
            session=session,
        )
        return res.modified_count

    async def soft_delete(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Soft-delete a model by setting is_deleted=True and is_default=False."""
        target_id = self._to_object_id(model_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        col = self.get_collection()
        res = await col.find_one_and_update(
            {"_id": target_id, "project_id": proj_id, "is_deleted": False},
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": now,
                    "is_default": False,
                    "updated_at": now,
                }
            },
            session=session,
        )
        return res is not None

    async def soft_delete_by_provider(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Cascading soft-delete all models belonging to a soft-deleted provider."""
        prov_id = self._to_object_id(provider_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        col = self.get_collection()
        res = await col.update_many(
            {"provider_id": prov_id, "project_id": proj_id, "is_deleted": False},
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": now,
                    "is_default": False,
                    "updated_at": now,
                }
            },
            session=session,
        )
        return res.modified_count

    async def purge(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Permanently delete a model document from MongoDB."""
        target_id = self._to_object_id(model_id)
        proj_id = self._to_object_id(project_id)

        col = self.get_collection()
        res = await col.delete_one({"_id": target_id, "project_id": proj_id}, session=session)
        return res.deleted_count > 0

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all models belonging to a project during project purge."""
        proj_id = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": proj_id}, session=session)
        return res.deleted_count


def get_project_model_repository() -> ProjectModelRepository:
    """Dependency provider for ProjectModelRepository."""
    return ProjectModelRepository()


__all__ = [
    "ProjectModelRepository",
    "get_project_model_repository",
    "translate_model_duplicate_key",
    "FakeProjectModelRepository",
]

# Re-export fake for backward-compatibility with tests importing from repository
try:
    from tests.fakes.fake_project_model_repository import FakeProjectModelRepository
except ImportError:
    pass
