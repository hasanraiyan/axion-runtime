"""
In-memory fake repository for ProjectCredential documents.
Used in unit and integration test suites to run entirely without MongoDB.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from beanie import PydanticObjectId

from app.core.exceptions import (
    ConflictError,
    CredentialRevisionConflictError,
    DuplicateCredentialNameError,
    NotFoundError,
)
from app.core.protocols.repositories import ICredentialRepository
from app.models.credential import CredentialStatus, ProjectCredential


class InMemoryProjectCredentialRepository(ICredentialRepository):
    """
    In-memory fake repository implementing ICredentialRepository.
    Used in unit and integration test suites to run entirely without MongoDB.
    """

    def __init__(self) -> None:
        self.credentials: Dict[str, ProjectCredential] = {}

    def _to_id_str(self, val: Any) -> str:
        return str(val)

    async def create(
        self,
        document: ProjectCredential,
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        # Check unique constraint on (project_id, name) where active
        for existing in self.credentials.values():
            if (
                not existing.is_deleted
                and existing.status == CredentialStatus.ACTIVE
                and str(existing.project_id) == str(document.project_id)
                and existing.name == document.name
            ):
                raise DuplicateCredentialNameError(document.name)
            if not existing.is_deleted and existing.key_hash == document.key_hash:
                raise ConflictError("Cryptographic key collision or duplicate key detected")

        if not hasattr(document, "id") or document.id is None:
            document.id = PydanticObjectId()
        now = datetime.now(timezone.utc)
        if not document.created_at:
            document.created_at = now
        document.updated_at = now
        self.credentials[str(document.id)] = document
        return document

    async def get_by_hash(self, key_hash: str) -> Optional[ProjectCredential]:
        for cred in self.credentials.values():
            if not cred.is_deleted and cred.key_hash == key_hash:
                return cred
        return None

    async def get_by_id_and_project(
        self,
        credential_id: Any,
        project_id: Any,
        include_deleted: bool = False,
    ) -> Optional[ProjectCredential]:
        cid_str = self._to_id_str(credential_id)
        pid_str = self._to_id_str(project_id)
        cred = self.credentials.get(cid_str)
        if cred and str(cred.project_id) == pid_str:
            if not include_deleted and cred.is_deleted:
                return None
            return cred
        return None

    async def list_by_project(
        self,
        project_id: Any,
        environment: Optional[str] = None,
        status: Optional[CredentialStatus] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectCredential], int]:
        pid_str = self._to_id_str(project_id)
        filtered = [
            c for c in self.credentials.values()
            if str(c.project_id) == pid_str
            and (include_deleted or not c.is_deleted)
            and (environment is None or c.environment == environment)
            and (status is None or c.status == status)
            and (
                search is None
                or search.lower() in c.name.lower()
                or (c.description and search.lower() in c.description.lower())
            )
        ]
        reverse = sort_order.lower() == "desc"
        filtered.sort(
            key=lambda x: getattr(x, sort_by, x.created_at) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=reverse,
        )
        return filtered[skip : skip + limit], len(filtered)

    async def update_with_revision(
        self,
        credential_id: Any,
        project_id: Any,
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        cred = await self.get_by_id_and_project(credential_id, project_id, include_deleted=True)
        if not cred:
            raise NotFoundError(f"Credential '{credential_id}' not found")
        if cred.is_deleted:
            raise ConflictError(f"Credential '{credential_id}' has been deleted")
        if cred.revision != expected_revision:
            raise CredentialRevisionConflictError(
                f"Credential revision mismatch (expected {expected_revision}, current {cred.revision})"
            )

        new_name = update_dict.get("name")
        if new_name and new_name != cred.name:
            for existing in self.credentials.values():
                if (
                    str(existing.id) != str(cred.id)
                    and not existing.is_deleted
                    and existing.status == CredentialStatus.ACTIVE
                    and str(existing.project_id) == str(cred.project_id)
                    and existing.name == new_name
                ):
                    raise DuplicateCredentialNameError(new_name)

        for k, v in update_dict.items():
            setattr(cred, k, v)
        cred.revision = expected_revision + 1
        cred.updated_at = datetime.now(timezone.utc)
        self.credentials[str(cred.id)] = cred
        return cred

    async def record_usage_debounced(
        self,
        credential_id: Any,
        client_ip: Optional[str] = None,
        current_last_used: Optional[datetime] = None,
        debounce_seconds: int = 300,
    ) -> bool:
        cid_str = self._to_id_str(credential_id)
        cred = self.credentials.get(cid_str)
        if not cred:
            return False
        now = datetime.now(timezone.utc)
        should_update = (
            current_last_used is None
            or (now - current_last_used).total_seconds() >= debounce_seconds
        )
        cred.total_uses += 1
        if should_update:
            cred.last_used_at = now
            cred.last_used_ip = client_ip
            return True
        return False

    async def revoke(
        self,
        credential_id: Any,
        project_id: Any,
        expected_revision: int,
        revoked_by: str,
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        cred = await self.get_by_id_and_project(credential_id, project_id)
        if cred and cred.status == CredentialStatus.REVOKED:
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
        credential_id: Any,
        project_id: Any,
        session: Optional[Any] = None,
    ) -> bool:
        cred = await self.get_by_id_and_project(credential_id, project_id)
        if cred:
            cred.is_deleted = True
            cred.deleted_at = datetime.now(timezone.utc)
            cred.updated_at = datetime.now(timezone.utc)
            return True
        return False

    async def purge(
        self,
        credential_id: Any,
        project_id: Any,
        session: Optional[Any] = None,
    ) -> bool:
        cid_str = self._to_id_str(credential_id)
        cred = await self.get_by_id_and_project(credential_id, project_id, include_deleted=True)
        if cred:
            del self.credentials[cid_str]
            return True
        return False

    async def purge_by_project(
        self,
        project_id: Any,
        session: Optional[Any] = None,
    ) -> int:
        pid_str = self._to_id_str(project_id)
        to_del = [cid for cid, c in self.credentials.items() if str(c.project_id) == pid_str]
        for cid in to_del:
            del self.credentials[cid]
        return len(to_del)
