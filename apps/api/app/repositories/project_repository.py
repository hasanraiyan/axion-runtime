"""
Project Repository providing data access and atomic operations for Project documents.
"""
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import ConflictError, InvalidStateTransitionError, NotFoundError
from app.models.project import Project, ProjectStatus
from app.repositories.base import BaseRepository


class ProjectRepository(BaseRepository[Project]):
    """
    Repository encapsulating all database interactions, atomic OCC updates,
    and FSM lifecycle state transitions for Project documents in MongoDB.
    """

    def __init__(self) -> None:
        super().__init__(Project)

    async def get_by_slug(self, slug: str) -> Optional[Project]:
        """Retrieve a project document by its unique slug."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"slug": slug})

    async def get_by_id_or_slug(self, identifier: Union[str, PydanticObjectId, ObjectId]) -> Optional[Project]:
        """
        Retrieve a project document by either its primary key ObjectId or unique slug.
        """
        if not self.is_db_ready():
            return None
        ident_str = str(identifier)
        doc = None
        if ObjectId.is_valid(ident_str):
            doc = await self.get_by_id(ident_str)
        if doc is None:
            doc = await self.get_by_slug(ident_str)
        return doc

    async def list_by_ids(
        self,
        project_ids: List[Union[PydanticObjectId, ObjectId, str]],
        status: Optional[ProjectStatus] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Project], int]:
        """
        List projects matching an ID set with optional filtering, search, sorting, and pagination.
        Returns a tuple of (projects, total_matching_count).
        """
        if not self.is_db_ready() or not project_ids:
            return ([], 0)

        obj_ids = [self._to_object_id(pid) for pid in project_ids]
        query: Dict[str, Any] = {"_id": {"$in": obj_ids}}

        if status is not None:
            query["status"] = status.value if hasattr(status, "value") else str(status)

        if tags:
            query["tags"] = {"$in": tags}

        if search:
            search_term = search.strip()
            if search_term:
                query["$or"] = [
                    {"name": {"$regex": re.escape(search_term), "$options": "i"}},
                    {"description": {"$regex": re.escape(search_term), "$options": "i"}},
                ]

        total = await self.count(query)
        if total == 0:
            return ([], 0)

        sort_prefix = "-" if sort_order.lower() == "desc" else "+"
        sort_field = sort_by if sort_by.startswith(("+", "-")) else f"{sort_prefix}{sort_by}"

        items = await self.find_many(query, skip=skip, limit=limit, sort=sort_field)
        return (items, total)

    async def create(self, document: Project, session: Optional[Any] = None) -> Project:
        """
        Insert a new Project document. Catches DuplicateKeyError on slug collisions
        and raises ConflictError.
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            raise ConflictError(f"Project with slug '{document.slug}' already exists") from exc

    async def update(self, document: Project, session: Optional[Any] = None) -> Project:
        """Update an existing Project document."""
        return await super().update(document, session=session)

    async def update_with_version(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str, Project],
        update_dict: Union[Dict[str, Any], int],
        expected_version: Optional[int] = None,
        session: Optional[Any] = None,
    ) -> Project:
        """
        Atomically update project document enforcing expected version for Optimistic Concurrency Control (OCC).
        Increments version and updates updated_at.
        Raises ConflictError if version does not match.
        """
        # Handle polymorphic arguments if called as update_with_version(project, expected_version, session)
        if isinstance(project_id, Project):
            proj_obj = project_id
            target_id = proj_obj.id
            if isinstance(update_dict, int):
                exp_ver = update_dict
                fields_to_update = proj_obj.model_dump(exclude={"id", "_id", "version", "updated_at"})
            else:
                exp_ver = expected_version if expected_version is not None else proj_obj.version
                fields_to_update = dict(update_dict)
        else:
            target_id = project_id
            if isinstance(update_dict, int):
                exp_ver = update_dict
                fields_to_update = {}
            else:
                if expected_version is None:
                    raise ValueError("expected_version must be provided")
                exp_ver = expected_version
                fields_to_update = dict(update_dict)

        now = datetime.now(timezone.utc)
        set_fields: Dict[str, Any] = {
            **fields_to_update,
            "version": exp_ver + 1,
            "updated_at": now,
        }

        query = {
            "_id": self._to_object_id(target_id),
            "version": exp_ver,
        }

        col = self.get_collection()
        res = await col.find_one_and_update(
            query,
            {"$set": set_fields},
            return_document=ReturnDocument.AFTER,
            session=session,
        )

        if res is None:
            existing = await self.get_by_id(target_id)
            if not existing:
                raise NotFoundError(f"Project '{target_id}' not found")
            if existing.version != exp_ver:
                raise ConflictError("Project version conflict: document was modified by a concurrent request")
            raise ConflictError("Project update conflict: document was modified by another concurrent request")

        if isinstance(res, Project):
            return res
        return self.model_class.model_validate(res)

    async def transition_status(
        self,
        project_id: Union[PydanticObjectId, ObjectId, str],
        from_state: ProjectStatus,
        to_state: ProjectStatus,
        expected_version: int,
        additional_updates: Optional[Dict[str, Any]] = None,
        session: Optional[Any] = None,
    ) -> Project:
        """
        Atomically transition project state while enforcing expected state and version (FSM CAS).
        Guarantees zero-collision state transitions under high concurrency.
        """
        now = datetime.now(timezone.utc)
        to_state_val = to_state.value if hasattr(to_state, "value") else str(to_state)
        from_state_val = from_state.value if hasattr(from_state, "value") else str(from_state)

        set_fields: Dict[str, Any] = {
            "status": to_state_val,
            "version": expected_version + 1,
            "updated_at": now,
        }
        if additional_updates:
            set_fields.update(additional_updates)

        query = {
            "_id": self._to_object_id(project_id),
            "status": from_state_val,
            "version": expected_version,
        }

        col = self.get_collection()
        res = await col.find_one_and_update(
            query,
            {"$set": set_fields},
            return_document=ReturnDocument.AFTER,
            session=session,
        )

        if res is None:
            existing = await self.get_by_id(project_id)
            if not existing:
                raise NotFoundError(f"Project '{project_id}' not found")
            existing_status_val = existing.status.value if hasattr(existing.status, "value") else str(existing.status)
            if existing_status_val != from_state_val:
                raise InvalidStateTransitionError(from_state=existing_status_val, to_state=to_state_val)
            if existing.version != expected_version:
                raise ConflictError("Project version conflict: document was modified by a concurrent request")
            raise ConflictError("Project state transition conflict")

        if isinstance(res, Project):
            return res
        return self.model_class.model_validate(res)


def get_project_repository() -> ProjectRepository:
    """FastAPI dependency provider for ProjectRepository."""
    return ProjectRepository()
