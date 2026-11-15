"""App resource repository (SRS-07 5.4)."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ReturnDocument

from app.core.protocols.tool_repositories import IAppResourceRepository
from app.models.app_resource import AppResource
from app.repositories.base import BaseRepository, serialize_for_mongo
from app.repositories.occ import occ_update

IdLike = Union[str, PydanticObjectId, ObjectId]


class AppResourceRepository(BaseRepository[AppResource], IAppResourceRepository):
    def __init__(self) -> None:
        super().__init__(AppResource)

    async def get_by_id_and_project(self, resource_id: IdLike, project_id: IdLike) -> Optional[AppResource]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"_id": self._to_object_id(resource_id), "project_id": self._to_object_id(project_id)})
        except ValueError:
            return None

    async def get_by_uri(self, integration_id: IdLike, uri: str) -> Optional[AppResource]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"integration_id": self._to_object_id(integration_id), "uri": uri})
        except ValueError:
            return None

    async def list_by_integration(self, project_id: IdLike, integration_id: IdLike) -> List[AppResource]:
        if not self.is_db_ready():
            return []
        return await self.find_many(
            {"project_id": self._to_object_id(project_id), "integration_id": self._to_object_id(integration_id)}, limit=500
        )

    async def save(self, document: AppResource) -> AppResource:
        existing = await self.get_by_uri(document.integration_id, document.uri)
        if existing is None:
            await document.insert()
            return document
        fields: Dict[str, Any] = serialize_for_mongo(document.model_dump(exclude={"id", "revision_id", "created_at"}))
        fields["revision"] = existing.revision + 1
        fields["updated_at"] = datetime.now(timezone.utc)
        result = await self.get_collection().find_one_and_update(
            {"_id": existing.id}, {"$set": fields}, return_document=ReturnDocument.AFTER
        )
        return result if isinstance(result, AppResource) else AppResource.model_validate(result)

    async def update_with_revision(self, resource_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]) -> AppResource:
        return await occ_update(
            AppResource, self.get_collection(), {"_id": self._to_object_id(resource_id)}, expected_revision,
            update_dict, label="App resource", deleted_flag_field=None,
        )

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


def get_app_resource_repository() -> AppResourceRepository:
    return AppResourceRepository()
