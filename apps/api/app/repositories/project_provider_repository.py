"""
Project Provider Repository providing data access, compound tenant queries,
atomic OCC updates, healthcheck recording, and soft-delete/purge operations
for ProjectProvider documents.
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
    DuplicateProviderNameError,
    DuplicateProviderSlugError,
    NotFoundError,
    ProviderRevisionConflictError,
)
from app.core.protocols.repositories import IProjectProviderRepository
from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.repositories.base import BaseRepository, serialize_for_mongo


def translate_provider_duplicate_key(exc: DuplicateKeyError, document: ProjectProvider) -> Exception:
    """Translate DuplicateKeyError by inspecting keyPattern."""
    key_pattern = (exc.details or {}).get("keyPattern", {})
    if "slug" in key_pattern:
        return DuplicateProviderSlugError(document.slug)
    if "name" in key_pattern:
        return DuplicateProviderNameError(document.name)
    fields = ", ".join(key_pattern.keys()) if key_pattern else "unique index"
    return ConflictError(f"Provider violates unique constraint on: {fields}")


class ProjectProviderRepository(BaseRepository[ProjectProvider], IProjectProviderRepository):
    """
    Repository encapsulating all database interactions, compound tenant queries,
    atomic OCC updates, and soft-delete/purge operations for ProjectProvider documents.
    """

    def __init__(self) -> None:
        super().__init__(ProjectProvider)

    async def create(
        self,
        document: ProjectProvider,
        session: Optional[Any] = None,
    ) -> ProjectProvider:
        """
        Insert a new ProjectProvider document. Translates DuplicateKeyError on
        (project_id, slug) or (project_id, name) into domain conflict errors.
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            raise translate_provider_duplicate_key(exc, document) from exc

    async def get_by_id_and_project(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        """Fetch a provider by primary key ensuring project boundary scoping."""
        if not self.is_db_ready():
            return None
        try:
            target_id = self._to_object_id(provider_id)
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

    async def get_by_slug(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        slug: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        """Fetch a provider by slug within a project."""
        if not self.is_db_ready():
            return None
        try:
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        query: Dict[str, Any] = {
            "project_id": proj_id,
            "slug": slug,
        }
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def get_by_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        name: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        """Fetch a provider by name within a project."""
        if not self.is_db_ready():
            return None
        try:
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        query: Dict[str, Any] = {
            "project_id": proj_id,
            "name": name,
        }
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_type: Optional[ProviderType] = None,
        status: Optional[ProviderStatus] = None,
        search: Optional[str] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectProvider], int]:
        """
        List providers for a project with optional filtering, search, sorting, and pagination.
        Returns a tuple of (providers, total_count).
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
        if provider_type is not None:
            query["provider_type"] = provider_type.value if isinstance(provider_type, ProviderType) else provider_type
        if status is not None:
            query["status"] = status.value if isinstance(status, ProviderStatus) else status

        if search:
            escaped_search = re.escape(search.strip())
            regex = {"$regex": escaped_search, "$options": "i"}
            query["$or"] = [{"name": regex}, {"slug": regex}]

        total_count = await self.count(query)
        if total_count == 0:
            return [], 0

        sort_dir = DESCENDING if sort_order.lower() == "desc" else ASCENDING
        valid_sort_fields = {"created_at", "updated_at", "name", "slug", "status"}
        applied_sort = sort_by if sort_by in valid_sort_fields else "updated_at"

        items = await self.find_many(
            query,
            skip=skip,
            limit=limit,
            sort=[(applied_sort, sort_dir)],
        )
        return items, total_count

    async def count_by_secret_id(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> int:
        """
        Count providers referencing a specific secret_id.
        Used to enforce the Secret Unlink Invariant (FR-08).
        """
        if not self.is_db_ready():
            return 0
        try:
            sec_id = self._to_object_id(secret_id)
        except ValueError:
            return 0

        query: Dict[str, Any] = {"secret_id": sec_id}
        if not include_deleted:
            query["is_deleted"] = False
        return await self.count(query)

    async def update_with_revision(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectProvider:
        """
        Atomically update provider document enforcing expected revision for OCC.
        Increments revision counter and sets updated_at.
        Raises ProviderRevisionConflictError if revision does not match.
        """
        target_id = self._to_object_id(provider_id)
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
            if "slug" in key_pattern:
                raise DuplicateProviderSlugError(str(update_dict.get("slug", "duplicate"))) from exc
            if "name" in key_pattern:
                raise DuplicateProviderNameError(str(update_dict.get("name", "duplicate"))) from exc
            fields = ", ".join(key_pattern.keys()) if key_pattern else "unique index"
            raise ConflictError(f"Provider violates unique constraint on: {fields}") from exc

        if res is None:
            existing = await self.get_by_id_and_project(provider_id, project_id, include_deleted=True)
            if not existing:
                raise NotFoundError(f"Provider '{provider_id}' not found")
            if existing.is_deleted:
                raise ConflictError(f"Provider '{provider_id}' has been deleted")
            if existing.revision != expected_revision:
                raise ProviderRevisionConflictError(
                    f"Provider '{provider_id}' revision conflict (expected {expected_revision}, current {existing.revision})"
                )
            raise ConflictError("Provider update conflict: concurrent modification detected")

        if isinstance(res, ProjectProvider):
            return res
        return self.model_class.model_validate(res)

    async def unset_other_defaults(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        exclude_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        session: Optional[Any] = None,
    ) -> int:
        """
        Atomically clear is_default on other active providers within the project.
        """
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)
        query: Dict[str, Any] = {
            "project_id": proj_id,
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

    async def update_healthcheck(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        healthcheck_status: HealthcheckStatus,
        latency_ms: Optional[int] = None,
        message: Optional[str] = None,
        status: Optional[ProviderStatus] = None,
        session: Optional[Any] = None,
    ) -> Optional[ProjectProvider]:
        """
        Record healthcheck execution outcome and optionally update provider operational status.
        """
        target_id = self._to_object_id(provider_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        update_ops: Dict[str, Any] = {
            "healthcheck_status": healthcheck_status.value if isinstance(healthcheck_status, HealthcheckStatus) else healthcheck_status,
            "last_healthcheck_at": now,
            "updated_at": now,
        }
        if latency_ms is not None:
            update_ops["healthcheck_latency_ms"] = latency_ms
        if message is not None:
            update_ops["healthcheck_message"] = message[:500]
        if status is not None:
            update_ops["status"] = status.value if isinstance(status, ProviderStatus) else status

        col = self.get_collection()
        res = await col.find_one_and_update(
            {"_id": target_id, "project_id": proj_id, "is_deleted": False},
            {"$set": update_ops},
            return_document=ReturnDocument.AFTER,
            session=session,
        )
        if res is None:
            return None
        if isinstance(res, ProjectProvider):
            return res
        return self.model_class.model_validate(res)

    async def soft_delete(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Soft-delete a provider document by setting is_deleted=True and unsetting is_default."""
        target_id = self._to_object_id(provider_id)
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

    async def purge(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Permanently delete a provider document from MongoDB."""
        target_id = self._to_object_id(provider_id)
        proj_id = self._to_object_id(project_id)

        col = self.get_collection()
        res = await col.delete_one({"_id": target_id, "project_id": proj_id}, session=session)
        return res.deleted_count > 0

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all providers belonging to a project during project purge."""
        proj_id = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": proj_id}, session=session)
        return res.deleted_count


def get_project_provider_repository() -> ProjectProviderRepository:
    """Dependency provider for ProjectProviderRepository."""
    return ProjectProviderRepository()


__all__ = [
    "ProjectProviderRepository",
    "get_project_provider_repository",
    "translate_provider_duplicate_key",
    "FakeProjectProviderRepository",
]

# Re-export fake for backward-compatibility with tests importing from repository
try:
    from tests.fakes.fake_project_provider_repository import FakeProjectProviderRepository
except ImportError:
    pass
