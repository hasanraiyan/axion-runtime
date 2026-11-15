"""Repositories for ToolDefinition, ToolSetting, and ToolBinding (SRS-07 5.2, 5.5)."""
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import ConflictError
from app.core.protocols.tool_repositories import (
    IToolBindingRepository,
    IToolDefinitionRepository,
    IToolSettingRepository,
)
from app.models.tool import (
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
    ToolDefinition,
    ToolSetting,
    ToolSyncState,
)
from app.repositories.base import BaseRepository, serialize_for_mongo
from app.repositories.occ import occ_update

IdLike = Union[str, PydanticObjectId, ObjectId]


class ToolDefinitionRepository(BaseRepository[ToolDefinition], IToolDefinitionRepository):
    def __init__(self) -> None:
        super().__init__(ToolDefinition)

    async def create_many(self, documents: List[ToolDefinition]) -> List[ToolDefinition]:
        if not documents:
            return []
        try:
            await self.model_class.insert_many(documents)
        except DuplicateKeyError as exc:
            raise ConflictError("A tool with the same tool_key already exists in this project") from exc
        return documents

    async def get_by_key(self, project_id: IdLike, tool_key: str) -> Optional[ToolDefinition]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"project_id": self._to_object_id(project_id), "tool_key": tool_key})
        except ValueError:
            return None

    async def list_by_integration(self, integration_id: IdLike) -> List[ToolDefinition]:
        if not self.is_db_ready():
            return []
        try:
            return await self.find_many({"integration_id": self._to_object_id(integration_id)}, limit=5000)
        except ValueError:
            return []

    async def list_by_keys(self, project_id: IdLike, tool_keys: List[str]) -> List[ToolDefinition]:
        if not self.is_db_ready() or not tool_keys:
            return []
        return await self.find_many(
            {"project_id": self._to_object_id(project_id), "tool_key": {"$in": tool_keys}}, limit=5000
        )

    async def list_by_project(
        self,
        project_id: IdLike,
        integration_id: Optional[IdLike] = None,
        sync_state: Optional[ToolSyncState] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ToolDefinition], int]:
        if not self.is_db_ready():
            return [], 0
        try:
            query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
            if integration_id is not None:
                query["integration_id"] = self._to_object_id(integration_id)
        except ValueError:
            return [], 0
        if sync_state is not None:
            query["sync_state"] = sync_state.value
        if search:
            regex = {"$regex": re.escape(search.strip()), "$options": "i"}
            query["$or"] = [{"tool_key": regex}, {"description": regex}]
        total = await self.count(query)
        if total == 0:
            return [], 0
        items = await self.find_many(query, skip=skip, limit=limit, sort=[("tool_key", ASCENDING)])
        return items, total

    async def update_definition(self, tool_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]) -> ToolDefinition:
        return await occ_update(
            ToolDefinition,
            self.get_collection(),
            {"_id": self._to_object_id(tool_id)},
            expected_revision,
            update_dict,
            label="Tool",
            deleted_flag_field=None,
        )

    async def set_sync_state(self, tool_ids: List[IdLike], state: ToolSyncState) -> int:
        if not tool_ids:
            return 0
        result = await self.get_collection().update_many(
            {"_id": {"$in": [self._to_object_id(i) for i in tool_ids]}},
            {"$set": {"sync_state": state.value}},
        )
        return result.modified_count

    async def delete_by_integration(self, integration_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"integration_id": self._to_object_id(integration_id)})
        return result.deleted_count

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class ToolSettingRepository(BaseRepository[ToolSetting], IToolSettingRepository):
    def __init__(self) -> None:
        super().__init__(ToolSetting)

    async def get_by_key(self, project_id: IdLike, tool_key: str) -> Optional[ToolSetting]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"project_id": self._to_object_id(project_id), "tool_key": tool_key})
        except ValueError:
            return None

    async def list_by_keys(self, project_id: IdLike, tool_keys: List[str]) -> List[ToolSetting]:
        if not self.is_db_ready() or not tool_keys:
            return []
        return await self.find_many(
            {"project_id": self._to_object_id(project_id), "tool_key": {"$in": tool_keys}}, limit=5000
        )

    async def get_or_create_default(self, project_id: IdLike, tool_key: str, defaults: Dict[str, Any]) -> ToolSetting:
        existing = await self.get_by_key(project_id, tool_key)
        if existing is not None:
            return existing
        document = ToolSetting(project_id=self._to_object_id(project_id), tool_key=tool_key, **defaults)
        try:
            await document.insert()
            return document
        except DuplicateKeyError:
            # Lost a creation race; the winner's document is authoritative.
            winner = await self.get_by_key(project_id, tool_key)
            if winner is None:
                raise
            return winner

    async def update_with_revision(
        self, project_id: IdLike, tool_key: str, expected_revision: int, update_dict: Dict[str, Any]
    ) -> ToolSetting:
        return await occ_update(
            ToolSetting,
            self.get_collection(),
            {"project_id": self._to_object_id(project_id), "tool_key": tool_key},
            expected_revision,
            update_dict,
            label="Tool setting",
            deleted_flag_field=None,
        )

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class ToolBindingRepository(BaseRepository[ToolBinding], IToolBindingRepository):
    def __init__(self) -> None:
        super().__init__(ToolBinding)

    async def list_by_project(
        self,
        project_id: IdLike,
        subject_type: Optional[BindingSubjectType] = None,
        subject_id: Optional[str] = None,
    ) -> List[ToolBinding]:
        if not self.is_db_ready():
            return []
        try:
            query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
        except ValueError:
            return []
        if subject_type is not None:
            query["subject_type"] = subject_type.value
        if subject_id is not None:
            query["subject_id"] = subject_id
        return await self.find_many(query, limit=5000)

    async def list_for_resolution(
        self, project_id: IdLike, agent_id: Optional[str], end_user_id: Optional[str]
    ) -> List[ToolBinding]:
        if not self.is_db_ready():
            return []
        clauses: List[Dict[str, Any]] = [{"subject_type": BindingSubjectType.PROJECT_DEFAULT.value}]
        if agent_id:
            clauses.append({"subject_type": BindingSubjectType.AGENT.value, "subject_id": agent_id})
        if end_user_id:
            clauses.append({"subject_type": BindingSubjectType.END_USER.value, "subject_id": end_user_id})
        return await self.find_many({"project_id": self._to_object_id(project_id), "$or": clauses}, limit=5000)

    async def replace_for_subject(
        self,
        project_id: IdLike,
        subject_type: BindingSubjectType,
        subject_id: Optional[str],
        bindings: List[ToolBinding],
    ) -> List[ToolBinding]:
        """
        Replace a subject's bindings. No transactions on standalone MongoDB (AGENTS invariant 8):
        the new set is inserted first, then superseded rules are removed, so a failure leaves a
        superset (deny rules still present) rather than an empty rule set.
        """
        pid = self._to_object_id(project_id)
        col = self.get_collection()
        existing = await self.find_many(
            {"project_id": pid, "subject_type": subject_type.value, "subject_id": subject_id}, limit=5000
        )
        keep_keys = {(b.target_type.value, b.target_id) for b in bindings}
        for doc in bindings:
            await col.replace_one(
                {
                    "project_id": pid,
                    "subject_type": subject_type.value,
                    "subject_id": subject_id,
                    "target_type": doc.target_type.value,
                    "target_id": doc.target_id,
                },
                serialize_for_mongo(doc.model_dump(by_alias=False, exclude={"id", "revision_id"})),
                upsert=True,
            )
        stale = [e.id for e in existing if (e.target_type.value, e.target_id) not in keep_keys]
        if stale:
            await col.delete_many({"_id": {"$in": stale}})
        return await self.find_many(
            {"project_id": pid, "subject_type": subject_type.value, "subject_id": subject_id}, limit=5000
        )

    async def delete_by_target(self, project_id: IdLike, target_type: BindingTargetType, target_id: str) -> int:
        result = await self.get_collection().delete_many(
            {"project_id": self._to_object_id(project_id), "target_type": target_type.value, "target_id": target_id}
        )
        return result.deleted_count

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


def get_tool_definition_repository() -> ToolDefinitionRepository:
    return ToolDefinitionRepository()


def get_tool_setting_repository() -> ToolSettingRepository:
    return ToolSettingRepository()


def get_tool_binding_repository() -> ToolBindingRepository:
    return ToolBindingRepository()
