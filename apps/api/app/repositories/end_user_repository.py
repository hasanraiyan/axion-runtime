"""End-user and invocation repositories (SRS-07 5.6, 5.9)."""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import NotFoundError
from app.core.protocols.tool_repositories import IEndUserRepository, IToolInvocationRepository
from app.models.end_user import EndUserStatus, ProjectEndUser
from app.models.tool_invocation import InvocationStatus, ToolInvocation
from app.repositories.base import BaseRepository, serialize_for_mongo

IdLike = Union[str, PydanticObjectId, ObjectId]


class EndUserRepository(BaseRepository[ProjectEndUser], IEndUserRepository):
    def __init__(self) -> None:
        super().__init__(ProjectEndUser)

    async def upsert_seen(
        self,
        project_id: IdLike,
        external_id: str,
        display_name: Optional[str],
        email: Optional[str],
        attributes: Optional[Dict[str, str]],
    ) -> Tuple[ProjectEndUser, bool]:
        """Create on first sight, otherwise refresh ``last_seen_at`` and supplied labels."""
        pid = self._to_object_id(project_id)
        existing = await self.get_by_external_id(pid, external_id)
        if existing is None:
            document = ProjectEndUser(
                project_id=pid,
                external_id=external_id,
                display_name=display_name,
                email=email,
                attributes=attributes or {},
            )
            try:
                await document.insert()
                return document, True
            except DuplicateKeyError:
                existing = await self.get_by_external_id(pid, external_id)
                if existing is None:
                    raise

        updates: Dict[str, Any] = {"last_seen_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
        if display_name is not None:
            updates["display_name"] = display_name
        if email is not None:
            updates["email"] = email
        if attributes is not None:
            updates["attributes"] = attributes
        result = await self.get_collection().find_one_and_update(
            {"_id": existing.id}, {"$set": serialize_for_mongo(updates)}, return_document=ReturnDocument.AFTER
        )
        refreshed = result if isinstance(result, ProjectEndUser) else ProjectEndUser.model_validate(result)
        return refreshed, False

    async def get_by_external_id(self, project_id: IdLike, external_id: str) -> Optional[ProjectEndUser]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"project_id": self._to_object_id(project_id), "external_id": external_id})
        except ValueError:
            return None

    async def get_by_id_and_project(self, end_user_id: IdLike, project_id: IdLike) -> Optional[ProjectEndUser]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one(
                {"_id": self._to_object_id(end_user_id), "project_id": self._to_object_id(project_id)}
            )
        except ValueError:
            return None

    async def list_by_project(
        self,
        project_id: IdLike,
        status: Optional[EndUserStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectEndUser], int]:
        if not self.is_db_ready():
            return [], 0
        try:
            query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
        except ValueError:
            return [], 0
        if status is not None:
            query["status"] = status.value
        if search:
            regex = {"$regex": re.escape(search.strip()), "$options": "i"}
            query["$or"] = [{"external_id": regex}, {"display_name": regex}]
        total = await self.count(query)
        if total == 0:
            return [], 0
        return await self.find_many(query, skip=skip, limit=limit, sort=[("last_seen_at", DESCENDING)]), total

    async def update_status(self, project_id: IdLike, external_id: str, status: EndUserStatus) -> ProjectEndUser:
        result = await self.get_collection().find_one_and_update(
            {"project_id": self._to_object_id(project_id), "external_id": external_id},
            {"$set": {"status": status.value, "updated_at": datetime.now(timezone.utc)}, "$inc": {"revision": 1}},
            return_document=ReturnDocument.AFTER,
        )
        if result is None:
            raise NotFoundError("End user not found")
        return result if isinstance(result, ProjectEndUser) else ProjectEndUser.model_validate(result)

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class ToolInvocationRepository(BaseRepository[ToolInvocation], IToolInvocationRepository):
    def __init__(self) -> None:
        super().__init__(ToolInvocation)

    async def list_by_project(
        self,
        project_id: IdLike,
        tool_key: Optional[str] = None,
        status: Optional[InvocationStatus] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ToolInvocation], int]:
        if not self.is_db_ready():
            return [], 0
        try:
            query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
        except ValueError:
            return [], 0
        if tool_key:
            query["tool_key"] = tool_key
        if status is not None:
            query["status"] = status.value
        total = await self.count(query)
        if total == 0:
            return [], 0
        return await self.find_many(query, skip=skip, limit=limit, sort=[("started_at", DESCENDING)]), total

    async def scrub_subject(self, project_id: IdLike, subject_id: str) -> int:
        """Right to erasure (FR-79): remove the subject id and arguments from matching records."""
        result = await self.get_collection().update_many(
            {"project_id": self._to_object_id(project_id), "subject.id": subject_id},
            {"$set": {"subject": {"type": "end_user", "id": None, "erased": True}, "arguments_redacted": {}, "result_summary.content": None, "result_summary.structured": None}},
        )
        return result.modified_count

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


def get_end_user_repository() -> EndUserRepository:
    return EndUserRepository()


def get_tool_invocation_repository() -> ToolInvocationRepository:
    return ToolInvocationRepository()
