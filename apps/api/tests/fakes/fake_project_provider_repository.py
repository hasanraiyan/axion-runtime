"""
In-memory fake repository for ProjectProvider documents.
Used in unit and integration tests without MongoDB.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId

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


class FakeProjectProviderRepository(IProjectProviderRepository):
    """
    In-memory fake repository implementing IProjectProviderRepository.
    Simulates unique indexes on (project_id, slug) and (project_id, name),
    OCC revision checks, soft deletion, and purge.
    """

    def __init__(self) -> None:
        self.providers: Dict[str, ProjectProvider] = {}

    def _to_id_str(self, val: Any) -> str:
        return str(val)

    async def create(
        self,
        document: ProjectProvider,
        session: Optional[Any] = None,
    ) -> ProjectProvider:
        doc_pid = self._to_id_str(document.project_id)
        # Check unique constraints on (project_id, slug) and (project_id, name)
        for existing in self.providers.values():
            if not existing.is_deleted and self._to_id_str(existing.project_id) == doc_pid:
                if existing.slug == document.slug:
                    raise DuplicateProviderSlugError(document.slug)
                if existing.name == document.name:
                    raise DuplicateProviderNameError(document.name)

        if not hasattr(document, "id") or document.id is None:
            document.id = PydanticObjectId()
        now = datetime.now(timezone.utc)
        if not document.created_at:
            document.created_at = now
        document.updated_at = now
        document.revision = 1
        self.providers[str(document.id)] = document.model_copy(deep=True)
        return document

    async def get_by_id_and_project(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        prov = self.providers.get(self._to_id_str(provider_id))
        if prov and self._to_id_str(prov.project_id) == self._to_id_str(project_id):
            if not include_deleted and prov.is_deleted:
                return None
            return prov.model_copy(deep=True)
        return None

    async def get_by_slug(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        slug: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        pid_str = self._to_id_str(project_id)
        for prov in self.providers.values():
            if self._to_id_str(prov.project_id) == pid_str and prov.slug == slug:
                if not include_deleted and prov.is_deleted:
                    return None
                return prov.model_copy(deep=True)
        return None

    async def get_by_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        name: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectProvider]:
        pid_str = self._to_id_str(project_id)
        for prov in self.providers.values():
            if self._to_id_str(prov.project_id) == pid_str and prov.name == name:
                if not include_deleted and prov.is_deleted:
                    return None
                return prov.model_copy(deep=True)
        return None

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
        pid_str = self._to_id_str(project_id)
        filtered = [
            p for p in self.providers.values()
            if self._to_id_str(p.project_id) == pid_str
            and (include_deleted or not p.is_deleted)
            and (provider_type is None or p.provider_type == provider_type)
            and (status is None or p.status == status)
            and (
                search is None
                or search.lower() in p.name.lower()
                or search.lower() in p.slug.lower()
            )
        ]

        reverse = sort_order.lower() == "desc"
        if sort_by in {"name", "slug"}:
            filtered.sort(key=lambda x: getattr(x, sort_by).lower(), reverse=reverse)
        else:
            filtered.sort(key=lambda x: getattr(x, sort_by, x.updated_at), reverse=reverse)

        total_count = len(filtered)
        paginated = filtered[skip : skip + limit]
        return [p.model_copy(deep=True) for p in paginated], total_count

    async def count_by_secret_id(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> int:
        sec_str = self._to_id_str(secret_id)
        return sum(
            1 for p in self.providers.values()
            if self._to_id_str(p.secret_id) == sec_str
            and (include_deleted or not p.is_deleted)
        )

    async def update_with_revision(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectProvider:
        prov = await self.get_by_id_and_project(provider_id, project_id, include_deleted=True)
        if not prov:
            raise NotFoundError(f"Provider '{provider_id}' not found")
        if prov.is_deleted:
            raise ConflictError(f"Provider '{provider_id}' has been deleted")
        if prov.revision != expected_revision:
            raise ProviderRevisionConflictError(
                f"Provider '{provider_id}' revision conflict (expected {expected_revision}, current {prov.revision})"
            )

        # Check unique constraint collisions if slug or name changed
        pid_str = self._to_id_str(project_id)
        target_id_str = self._to_id_str(provider_id)
        new_slug = update_dict.get("slug")
        new_name = update_dict.get("name")
        for other in self.providers.values():
            if (
                str(other.id) != target_id_str
                and not other.is_deleted
                and self._to_id_str(other.project_id) == pid_str
            ):
                if new_slug and other.slug == new_slug:
                    raise DuplicateProviderSlugError(new_slug)
                if new_name and other.name == new_name:
                    raise DuplicateProviderNameError(new_name)

        now = datetime.now(timezone.utc)
        stored = self.providers[target_id_str]
        for k, v in update_dict.items():
            if hasattr(stored, k):
                setattr(stored, k, v)
        stored.revision = expected_revision + 1
        stored.updated_at = now
        return stored.model_copy(deep=True)

    async def unset_other_defaults(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        exclude_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        exc_str = self._to_id_str(exclude_id) if exclude_id is not None else None
        now = datetime.now(timezone.utc)
        count = 0
        for p in self.providers.values():
            if (
                self._to_id_str(p.project_id) == pid_str
                and not p.is_deleted
                and p.is_default
                and str(p.id) != exc_str
            ):
                p.is_default = False
                p.updated_at = now
                count += 1
        return count

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
        prov = await self.get_by_id_and_project(provider_id, project_id)
        if not prov:
            return None
        now = datetime.now(timezone.utc)
        target = self.providers[str(prov.id)]
        target.healthcheck_status = healthcheck_status
        target.last_healthcheck_at = now
        target.updated_at = now
        if latency_ms is not None:
            target.healthcheck_latency_ms = latency_ms
        if message is not None:
            target.healthcheck_message = message[:500]
        if status is not None:
            target.status = status
        return target.model_copy(deep=True)

    async def soft_delete(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        prov = await self.get_by_id_and_project(provider_id, project_id)
        if not prov:
            return False
        now = datetime.now(timezone.utc)
        target = self.providers[str(prov.id)]
        target.is_deleted = True
        target.deleted_at = now
        target.is_default = False
        target.updated_at = now
        return True

    async def purge(
        self,
        provider_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        prov = await self.get_by_id_and_project(provider_id, project_id, include_deleted=True)
        if not prov:
            return False
        del self.providers[str(prov.id)]
        return True

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        to_del = [k for k, v in self.providers.items() if self._to_id_str(v.project_id) == pid_str]
        for k in to_del:
            del self.providers[k]
        return len(to_del)
