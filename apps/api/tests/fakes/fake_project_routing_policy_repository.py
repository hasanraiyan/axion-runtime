"""
In-memory fake repository for ProjectRoutingPolicy documents.
Used in unit and integration tests without MongoDB.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import ConflictError, NotFoundError
from app.core.protocols.repositories import IProjectRoutingPolicyRepository
from app.models.project_routing_policy import ProjectRoutingPolicy


class FakeProjectRoutingPolicyRepository(IProjectRoutingPolicyRepository):
    """
    In-memory fake repository implementing IProjectRoutingPolicyRepository.
    Simulates OCC revision updates, filtering by active status, and project purge.
    """

    def __init__(self) -> None:
        self.policies: Dict[str, ProjectRoutingPolicy] = {}

    def _to_id_str(self, val: Any) -> str:
        return str(val)

    async def create(
        self,
        document: ProjectRoutingPolicy,
        session: Optional[Any] = None,
    ) -> ProjectRoutingPolicy:
        if not hasattr(document, "id") or document.id is None:
            document.id = PydanticObjectId()
        now = datetime.now(timezone.utc)
        if not document.created_at:
            document.created_at = now
        document.updated_at = now
        document.revision = 1
        self.policies[str(document.id)] = document.model_copy(deep=True)
        return document

    async def get_by_id_and_project(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
    ) -> Optional[ProjectRoutingPolicy]:
        pol = self.policies.get(self._to_id_str(policy_id))
        if pol and self._to_id_str(pol.project_id) == self._to_id_str(project_id):
            return pol.model_copy(deep=True)
        return None

    async def get_by_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        name: str,
    ) -> Optional[ProjectRoutingPolicy]:
        pid_str = self._to_id_str(project_id)
        for pol in self.policies.values():
            if self._to_id_str(pol.project_id) == pid_str and pol.name == name:
                return pol.model_copy(deep=True)
        return None

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        is_active: Optional[bool] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectRoutingPolicy], int]:
        pid_str = self._to_id_str(project_id)
        filtered = [
            p for p in self.policies.values()
            if self._to_id_str(p.project_id) == pid_str
            and (is_active is None or p.is_active == is_active)
        ]
        filtered.sort(key=lambda x: x.name)
        total_count = len(filtered)
        paginated = filtered[skip : skip + limit]
        return [p.model_copy(deep=True) for p in paginated], total_count

    async def update_with_revision(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectRoutingPolicy:
        pol = await self.get_by_id_and_project(policy_id, project_id)
        if not pol:
            raise NotFoundError(f"Routing policy '{policy_id}' not found")
        if pol.revision != expected_revision:
            raise ConflictError(
                f"Routing policy '{policy_id}' revision conflict (expected {expected_revision}, current {pol.revision})"
            )

        now = datetime.now(timezone.utc)
        stored = self.policies[self._to_id_str(policy_id)]
        for k, v in update_dict.items():
            if hasattr(stored, k):
                setattr(stored, k, v)
        stored.revision = expected_revision + 1
        stored.updated_at = now
        return stored.model_copy(deep=True)

    async def delete(
        self,
        policy_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        pol = await self.get_by_id_and_project(policy_id, project_id)
        if not pol:
            return False
        del self.policies[self._to_id_str(policy_id)]
        return True

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        to_del = [k for k, v in self.policies.items() if self._to_id_str(v.project_id) == pid_str]
        for k in to_del:
            del self.policies[k]
        return len(to_del)
