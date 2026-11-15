"""
In-memory fake repository for ProjectModel documents.
Used in unit and integration tests without MongoDB.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import (
    ConflictError,
    DuplicateModelError,
    ModelRevisionConflictError,
    NotFoundError,
)
from app.core.protocols.repositories import IProjectModelRepository
from app.models.project_model import ModelType, ProjectModel


class FakeProjectModelRepository(IProjectModelRepository):
    """
    In-memory fake repository implementing IProjectModelRepository.
    Simulates unique indexes on (provider_id, model_id), capability filters,
    OCC revision checks, soft deletion, and purge.
    """

    def __init__(self) -> None:
        self.models: Dict[str, ProjectModel] = {}

    def _to_id_str(self, val: Any) -> str:
        return str(val)

    async def create(
        self,
        document: ProjectModel,
        session: Optional[Any] = None,
    ) -> ProjectModel:
        prov_id_str = self._to_id_str(document.provider_id)
        # Check unique constraint on (provider_id, model_id) where active
        for existing in self.models.values():
            if (
                not existing.is_deleted
                and self._to_id_str(existing.provider_id) == prov_id_str
                and existing.model_id == document.model_id
            ):
                raise DuplicateModelError(document.model_id)

        if not hasattr(document, "id") or document.id is None:
            document.id = PydanticObjectId()
        now = datetime.now(timezone.utc)
        if not document.created_at:
            document.created_at = now
        document.updated_at = now
        document.revision = 1
        self.models[str(document.id)] = document.model_copy(deep=True)
        return document

    async def get_by_id_and_project(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectModel]:
        m = self.models.get(self._to_id_str(model_id))
        if m and self._to_id_str(m.project_id) == self._to_id_str(project_id):
            if not include_deleted and m.is_deleted:
                return None
            return m.model_copy(deep=True)
        return None

    async def get_by_provider_and_model_id(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        model_id: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectModel]:
        prov_id_str = self._to_id_str(provider_id)
        for m in self.models.values():
            if self._to_id_str(m.provider_id) == prov_id_str and m.model_id == model_id:
                if not include_deleted and m.is_deleted:
                    return None
                return m.model_copy(deep=True)
        return None

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
        pid_str = self._to_id_str(project_id)
        prov_str = self._to_id_str(provider_id) if provider_id is not None else None

        filtered = [
            m for m in self.models.values()
            if self._to_id_str(m.project_id) == pid_str
            and (include_deleted or not m.is_deleted)
            and (prov_str is None or self._to_id_str(m.provider_id) == prov_str)
            and (model_type is None or m.model_type == model_type)
            and (supports_tools is None or m.supports_tools == supports_tools)
            and (supports_vision is None or m.supports_vision == supports_vision)
            and (supports_json_mode is None or m.supports_json_mode == supports_json_mode)
            and (is_enabled is None or m.is_enabled == is_enabled)
            and (
                search is None
                or search.lower() in m.model_id.lower()
                or search.lower() in m.display_name.lower()
            )
        ]

        reverse = sort_order.lower() == "desc"
        if sort_by in {"model_id", "display_name"}:
            filtered.sort(key=lambda x: getattr(x, sort_by).lower(), reverse=reverse)
        else:
            filtered.sort(key=lambda x: getattr(x, sort_by, x.created_at), reverse=reverse)

        total_count = len(filtered)
        paginated = filtered[skip : skip + limit]
        return [m.model_copy(deep=True) for m in paginated], total_count

    async def list_by_provider(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> List[ProjectModel]:
        prov_str = self._to_id_str(provider_id)
        res = [
            m.model_copy(deep=True)
            for m in self.models.values()
            if self._to_id_str(m.provider_id) == prov_str
            and (include_deleted or not m.is_deleted)
        ]
        res.sort(key=lambda x: x.model_id)
        return res

    async def update_with_revision(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectModel:
        m = await self.get_by_id_and_project(model_id, project_id, include_deleted=True)
        if not m:
            raise NotFoundError(f"Model '{model_id}' not found")
        if m.is_deleted:
            raise ConflictError(f"Model '{model_id}' has been deleted")
        if m.revision != expected_revision:
            raise ModelRevisionConflictError(
                f"Model '{model_id}' revision conflict (expected {expected_revision}, current {m.revision})"
            )

        mid_str = self._to_id_str(model_id)
        new_model_id = update_dict.get("model_id")
        if new_model_id:
            prov_str = self._to_id_str(m.provider_id)
            for other in self.models.values():
                if (
                    str(other.id) != mid_str
                    and not other.is_deleted
                    and self._to_id_str(other.provider_id) == prov_str
                    and other.model_id == new_model_id
                ):
                    raise DuplicateModelError(new_model_id)

        now = datetime.now(timezone.utc)
        stored = self.models[mid_str]
        for k, v in update_dict.items():
            if hasattr(stored, k):
                setattr(stored, k, v)
        stored.revision = expected_revision + 1
        stored.updated_at = now
        return stored.model_copy(deep=True)

    async def unset_other_defaults(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        model_type: ModelType,
        exclude_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        exc_str = self._to_id_str(exclude_id) if exclude_id is not None else None
        now = datetime.now(timezone.utc)
        count = 0
        for m in self.models.values():
            if (
                self._to_id_str(m.project_id) == pid_str
                and not m.is_deleted
                and m.model_type == model_type
                and m.is_default
                and str(m.id) != exc_str
            ):
                m.is_default = False
                m.updated_at = now
                count += 1
        return count

    async def soft_delete(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        m = await self.get_by_id_and_project(model_id, project_id)
        if not m:
            return False
        now = datetime.now(timezone.utc)
        target = self.models[str(m.id)]
        target.is_deleted = True
        target.deleted_at = now
        target.is_default = False
        target.updated_at = now
        return True

    async def soft_delete_by_provider(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        prov_str = self._to_id_str(provider_id)
        pid_str = self._to_id_str(project_id)
        now = datetime.now(timezone.utc)
        count = 0
        for m in self.models.values():
            if (
                self._to_id_str(m.provider_id) == prov_str
                and self._to_id_str(m.project_id) == pid_str
                and not m.is_deleted
            ):
                m.is_deleted = True
                m.deleted_at = now
                m.is_default = False
                m.updated_at = now
                count += 1
        return count

    async def purge(
        self,
        model_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        m = await self.get_by_id_and_project(model_id, project_id, include_deleted=True)
        if not m:
            return False
        del self.models[str(m.id)]
        return True

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        to_del = [k for k, v in self.models.items() if self._to_id_str(v.project_id) == pid_str]
        for k in to_del:
            del self.models[k]
        return len(to_del)
