"""Integration repository: all MongoDB access for ``project_integrations`` (SRS-07)."""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import (
    ConflictError,
    DuplicateIntegrationNameError,
    DuplicateIntegrationSlugError,
)
from app.core.protocols.tool_repositories import IIntegrationRepository
from app.models.integration import Integration, IntegrationStatus, IntegrationType
from app.repositories.base import BaseRepository, serialize_for_mongo
from app.repositories.occ import occ_update

IdLike = Union[str, PydanticObjectId, ObjectId]


def translate_integration_duplicate_key(exc: DuplicateKeyError, document: Integration) -> Exception:
    """Report only the constraint that actually failed (AGENTS invariant 3)."""
    key_pattern = (exc.details or {}).get("keyPattern", {})
    if "slug" in key_pattern:
        return DuplicateIntegrationSlugError(document.slug)
    if "name" in key_pattern:
        return DuplicateIntegrationNameError(document.name)
    fields = ", ".join(key_pattern.keys()) if key_pattern else "unique index"
    return ConflictError(f"Integration violates unique constraint on: {fields}")


class IntegrationRepository(BaseRepository[Integration], IIntegrationRepository):
    def __init__(self) -> None:
        super().__init__(Integration)

    async def create(self, document: Integration, session: Optional[Any] = None) -> Integration:
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            raise translate_integration_duplicate_key(exc, document) from exc

    async def get_by_id_and_project(
        self, integration_id: IdLike, project_id: IdLike, include_deleted: bool = False
    ) -> Optional[Integration]:
        if not self.is_db_ready():
            return None
        try:
            query: Dict[str, Any] = {
                "_id": self._to_object_id(integration_id),
                "project_id": self._to_object_id(project_id),
            }
        except ValueError:
            return None
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def get_by_slug(self, project_id: IdLike, slug: str) -> Optional[Integration]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"project_id": self._to_object_id(project_id), "slug": slug})
        except ValueError:
            return None

    async def list_by_project(
        self,
        project_id: IdLike,
        type: Optional[IntegrationType] = None,
        status: Optional[IntegrationStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[Integration], int]:
        if not self.is_db_ready():
            return [], 0
        try:
            query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
        except ValueError:
            return [], 0
        if not include_deleted:
            query["is_deleted"] = False
        if type is not None:
            query["type"] = type.value
        if status is not None:
            query["status"] = status.value
        if search:
            regex = {"$regex": re.escape(search.strip()), "$options": "i"}
            query["$or"] = [{"name": regex}, {"slug": regex}]
        total = await self.count(query)
        if total == 0:
            return [], 0
        items = await self.find_many(query, skip=skip, limit=limit, sort=[("updated_at", DESCENDING)])
        return items, total

    async def update_with_revision(
        self,
        integration_id: IdLike,
        project_id: IdLike,
        expected_revision: int,
        update_dict: Dict[str, Any],
        include_deleted: bool = False,
    ) -> Integration:
        base = {"_id": self._to_object_id(integration_id), "project_id": self._to_object_id(project_id)}
        try:
            return await occ_update(
                Integration,
                self.get_collection(),
                base,
                expected_revision,
                update_dict,
                label="Integration",
                allow_deleted=include_deleted,
            )
        except DuplicateKeyError as exc:
            key_pattern = (exc.details or {}).get("keyPattern", {})
            if "name" in key_pattern:
                raise DuplicateIntegrationNameError(str(update_dict.get("name", "duplicate"))) from exc
            raise ConflictError("Integration violates a unique constraint") from exc

    async def update_runtime_state(self, integration_id: IdLike, project_id: IdLike, update_dict: Dict[str, Any]) -> None:
        """Write runtime-owned fields (status, health, failure counters) without touching revision."""
        await self.get_collection().update_one(
            {"_id": self._to_object_id(integration_id), "project_id": self._to_object_id(project_id)},
            {"$set": serialize_for_mongo({**update_dict, "updated_at": datetime.now(timezone.utc)})},
        )

    async def find_referencing_secret(self, project_id: IdLike, secret_id: IdLike) -> List[Integration]:
        if not self.is_db_ready():
            return []
        try:
            query = {
                "project_id": self._to_object_id(project_id),
                "referenced_secret_ids": self._to_object_id(secret_id),
                "is_deleted": False,
            }
        except ValueError:
            return []
        return await self.find_many(query, limit=1000)

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


def get_integration_repository() -> IntegrationRepository:
    return IntegrationRepository()
