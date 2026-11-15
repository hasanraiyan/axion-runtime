"""
Project Credential Repository providing data access, compound tenant queries,
atomic OCC updates, and soft-delete/purge operations for ProjectCredential documents.
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
    CredentialRevisionConflictError,
    DuplicateCredentialNameError,
    NotFoundError,
)
from app.core.protocols.repositories import ICredentialRepository
from app.models.credential import CredentialStatus, ProjectCredential
from app.repositories.base import BaseRepository, serialize_for_mongo


class ProjectCredentialRepository(BaseRepository[ProjectCredential], ICredentialRepository):
    """
    Repository encapsulating all database interactions, compound tenant queries,
    atomic OCC updates, and soft-delete/purge operations for ProjectCredential documents.
    Implements ICredentialRepository.
    """

    def __init__(self) -> None:
        super().__init__(ProjectCredential)

    async def create(
        self,
        document: ProjectCredential,
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        """
        Insert a new ProjectCredential document.
        Translates DuplicateKeyError by inspecting keyPattern:
        - idx_credentials_project_name_unique -> DuplicateCredentialNameError
        - idx_credentials_key_hash_unique -> ConflictError key collision
        """
        try:
            return await super().create(document, session=session)
        except DuplicateKeyError as exc:
            key_pattern = (exc.details or {}).get("keyPattern", {})
            if "name" in key_pattern:
                raise DuplicateCredentialNameError(document.name) from exc
            if "key_hash" in key_pattern:
                raise ConflictError("Cryptographic key collision or duplicate key detected") from exc
            fields = ", ".join(key_pattern)
            raise ConflictError(f"Credential violates a unique constraint on: {fields}") from exc

    async def get_by_hash(self, key_hash: str) -> Optional[ProjectCredential]:
        """Fetch active credential by SHA-256 hash with sub-millisecond index lookup."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"key_hash": key_hash, "is_deleted": False})

    async def get_by_id_and_project(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectCredential]:
        """Fetch a credential by primary key ID ensuring project tenant boundary."""
        if not self.is_db_ready():
            return None
        try:
            target_id = self._to_object_id(credential_id)
            proj_id = self._to_object_id(project_id)
        except ValueError:
            return None

        query: Dict[str, Any] = {"_id": target_id, "project_id": proj_id}
        if not include_deleted:
            query["is_deleted"] = False
        return await self.find_one(query)

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: Optional[str] = None,
        status: Optional[CredentialStatus] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectCredential], int]:
        """List credentials for a project with filtering, search, and pagination."""
        if not self.is_db_ready():
            return [], 0

        query: Dict[str, Any] = {"project_id": self._to_object_id(project_id)}
        if not include_deleted:
            query["is_deleted"] = False
        if environment:
            query["environment"] = environment
        if status:
            query["status"] = status

        if search:
            escaped = re.escape(search)
            query["$or"] = [
                {"name": {"$regex": escaped, "$options": "i"}},
                {"description": {"$regex": escaped, "$options": "i"}},
            ]

        allowed_sorts = {
            "name": "name",
            "created_at": "created_at",
            "updated_at": "updated_at",
            "last_used_at": "last_used_at",
            "expires_at": "expires_at",
            "revision": "revision",
        }
        sort_field = allowed_sorts.get(sort_by, "created_at")
        sort_direction = DESCENDING if sort_order.lower() == "desc" else ASCENDING

        total = await self.count(query)
        items = await self.find_many(
            query,
            skip=skip,
            limit=limit,
            sort=[(sort_field, sort_direction)],
        )
        return items, total

    async def update_with_revision(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        """
        Atomically update credential document enforcing expected revision for OCC.
        Serializes payload via serialize_for_mongo.
        Raises NotFoundError if document missing, ConflictError if modified concurrently.
        """
        target_id = self._to_object_id(credential_id)
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
            if "name" in key_pattern:
                raise DuplicateCredentialNameError(str(update_dict.get("name", ""))) from exc
            fields = ", ".join(key_pattern)
            raise ConflictError(f"Credential violates a unique constraint on: {fields}") from exc

        if res is None:
            existing = await self.get_by_id_and_project(credential_id, project_id, include_deleted=True)
            if not existing:
                raise NotFoundError(f"Credential '{credential_id}' not found")
            if existing.is_deleted:
                raise ConflictError(f"Credential '{credential_id}' has been deleted")
            if existing.revision != expected_revision:
                raise CredentialRevisionConflictError(
                    f"Credential revision mismatch (expected {expected_revision}, current {existing.revision})"
                )
            raise CredentialRevisionConflictError("Credential update conflict: concurrent modification detected")

        if isinstance(res, ProjectCredential):
            return res
        return self.model_class.model_validate(res)

    async def record_usage_debounced(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        client_ip: Optional[str] = None,
        current_last_used: Optional[datetime] = None,
        debounce_seconds: int = 300,
    ) -> bool:
        """
        Updates last_used_at and last_used_ip with write-debouncing (default 5 min).
        Always increments total_uses via atomic $inc so counts are never dropped.
        """
        now = datetime.now(timezone.utc)
        target_id = self._to_object_id(credential_id)
        col = self.get_collection()

        should_update_timestamp = (
            current_last_used is None
            or (now - current_last_used).total_seconds() >= debounce_seconds
        )

        update_ops: Dict[str, Any] = {"$inc": {"total_uses": 1}}
        if should_update_timestamp:
            update_ops["$set"] = {
                "last_used_at": now,
                "last_used_ip": client_ip,
            }

        res = await col.update_one({"_id": target_id}, update_ops)
        return res.modified_count > 0

    async def revoke(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        revoked_by: str,
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        """Atomically transition credential to REVOKED status with OCC revision increment."""
        existing = await self.get_by_id_and_project(credential_id, project_id)
        if existing and existing.status == CredentialStatus.REVOKED:
            raise ConflictError("Credential is already revoked")
        now = datetime.now(timezone.utc)
        return await self.update_with_revision(
            credential_id=credential_id,
            project_id=project_id,
            expected_revision=expected_revision,
            update_dict={
                "status": CredentialStatus.REVOKED,
                "revoked_at": now,
                "revoked_by": revoked_by,
            },
            session=session,
        )

    async def soft_delete(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Soft-delete credential by setting is_deleted=True."""
        target_id = self._to_object_id(credential_id)
        proj_id = self._to_object_id(project_id)
        now = datetime.now(timezone.utc)

        col = self.get_collection()
        res = await col.find_one_and_update(
            {"_id": target_id, "project_id": proj_id, "is_deleted": False},
            {"$set": {"is_deleted": True, "deleted_at": now, "updated_at": now}},
            session=session,
        )
        return res is not None

    async def purge(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        """Permanently delete a credential document from MongoDB."""
        target_id = self._to_object_id(credential_id)
        proj_id = self._to_object_id(project_id)

        col = self.get_collection()
        res = await col.delete_one({"_id": target_id, "project_id": proj_id}, session=session)
        return res.deleted_count > 0

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        """Permanently delete all credentials belonging to a project during project purge."""
        proj_id = self._to_object_id(project_id)
        col = self.get_collection()
        res = await col.delete_many({"project_id": proj_id}, session=session)
        return res.deleted_count


def get_credential_repository() -> ProjectCredentialRepository:
    """Dependency provider for ProjectCredentialRepository."""
    return ProjectCredentialRepository()


__all__ = [
    "ProjectCredentialRepository",
    "get_credential_repository",
    "InMemoryProjectCredentialRepository",
]

# Re-export fake for backward-compatibility with tests importing from repository
try:
    from tests.fakes.credential_repository import InMemoryProjectCredentialRepository
except ImportError:
    pass
