"""
Project Audit Repository providing append-only logging and retrieval for ProjectAuditLog documents.
"""
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId

from app.models.project import ProjectAuditAction, ProjectAuditLog
from app.repositories.base import BaseRepository


class ProjectAuditRepository(BaseRepository[ProjectAuditLog]):
    """
    Repository encapsulating audit trail operations for Project audit records.
    Audit logs are strictly append-only.
    """

    def __init__(self) -> None:
        super().__init__(ProjectAuditLog)

    async def log_event(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        actor_id: str,
        action: Union[ProjectAuditAction, str],
        payload: Dict[str, Any],
        target_user_id: Optional[str] = None,
        session: Optional[Any] = None,
    ) -> ProjectAuditLog:
        """
        Record an immutable audit event in the project audit log collection.
        """
        pid = self._to_object_id(project_id)
        action_enum = action if isinstance(action, ProjectAuditAction) else ProjectAuditAction(action)
        audit_log = ProjectAuditLog(
            project_id=pid,
            actor_id=actor_id,
            action=action_enum,
            target_user_id=target_user_id,
            payload=payload,
        )
        return await self.create(audit_log, session=session)

    async def list_events(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        skip: Union[int, Any] = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectAuditLog], int]:
        """
        List audit events for a project ordered newest first (descending created_at).
        Supports both (skip, limit) and pagination_params objects.
        Returns a tuple of (audit_logs, total_count).
        """
        if not self.is_db_ready():
            return ([], 0)

        # Handle pagination_params object if passed as first pagination argument
        if not isinstance(skip, int):
            if hasattr(skip, "offset") and hasattr(skip, "limit"):
                actual_skip = getattr(skip, "offset", 0)
                actual_limit = getattr(skip, "limit", 50)
            elif hasattr(skip, "page") and hasattr(skip, "page_size"):
                page = getattr(skip, "page", 1)
                size = getattr(skip, "page_size", 50)
                actual_skip = max(0, (page - 1) * size)
                actual_limit = size
            else:
                actual_skip = 0
                actual_limit = limit
        else:
            actual_skip = skip
            actual_limit = limit

        pid = self._to_object_id(project_id)
        query = {"project_id": pid}

        total = await self.count(query)
        if total == 0:
            return ([], 0)

        items = await self.find_many(query, skip=actual_skip, limit=actual_limit, sort="-created_at")
        return (items, total)

    async def delete_by_project_id(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all audit logs of a project (used during project purge)."""
        pid = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": pid}, session=session)
        return res.deleted_count


def get_project_audit_repository() -> ProjectAuditRepository:
    """FastAPI dependency provider for ProjectAuditRepository."""
    return ProjectAuditRepository()
