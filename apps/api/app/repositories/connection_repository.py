"""Repositories for connections, connect sessions, OAuth clients, and tool policy (SRS-07 5.3, 5.10, 5.11)."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from pymongo import DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.crypto.envelope import EncryptedEnvelope
from app.core.protocols.tool_repositories import (
    IConnectionRepository,
    IConnectSessionRepository,
    IOAuthClientRepository,
    IToolPolicyRepository,
)
from app.models.connection import (
    ConnectionStatus,
    ConnectionSubjectType,
    ConnectSession,
    ConnectSessionStatus,
    CredentialKind,
    IntegrationConnection,
    IntegrationOAuthClient,
    ProjectToolPolicy,
)
from app.repositories.base import BaseRepository, serialize_for_mongo
from app.repositories.occ import occ_update

IdLike = Union[str, PydanticObjectId, ObjectId]


def _doc(model: Any, result: Any) -> Any:
    return result if isinstance(result, model) else model.model_validate(result)


class ConnectionRepository(BaseRepository[IntegrationConnection], IConnectionRepository):
    def __init__(self) -> None:
        super().__init__(IntegrationConnection)

    async def save_credentials(
        self,
        project_id: IdLike,
        integration_id: IdLike,
        subject_type: ConnectionSubjectType,
        subject_id: Optional[str],
        subject_key: str,
        kind: CredentialKind,
        access_envelope: EncryptedEnvelope,
        refresh_envelope: Optional[EncryptedEnvelope],
        expires_at: Optional[datetime],
        granted_scopes: List[str],
        external_account: Dict[str, Any],
    ) -> IntegrationConnection:
        """Create or replace the one connection for ``(integration, subject)``; reconnecting resets it to active."""
        now = datetime.now(timezone.utc)
        fields = serialize_for_mongo(
            {
                "credential_kind": kind,
                "access_envelope": access_envelope,
                "refresh_envelope": refresh_envelope,
                "expires_at": expires_at,
                "granted_scopes": granted_scopes,
                "external_account": external_account,
                "status": ConnectionStatus.ACTIVE,
                "last_error": None,
                "last_error_at": None,
                "updated_at": now,
            }
        )
        on_insert = serialize_for_mongo(
            {
                "project_id": self._to_object_id(project_id),
                "integration_id": self._to_object_id(integration_id),
                "subject_type": subject_type,
                "subject_id": subject_id,
                "subject_key": subject_key,
                "created_at": now,
                "last_used_at": None,
            }
        )
        try:
            result = await self.get_collection().find_one_and_update(
                {"integration_id": self._to_object_id(integration_id), "subject_key": subject_key},
                {"$set": fields, "$setOnInsert": on_insert, "$inc": {"revision": 1}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError:  # lost a creation race: retry as a plain update
            result = await self.get_collection().find_one_and_update(
                {"integration_id": self._to_object_id(integration_id), "subject_key": subject_key},
                {"$set": fields, "$inc": {"revision": 1}},
                return_document=ReturnDocument.AFTER,
            )
        return _doc(IntegrationConnection, result)

    async def get(self, integration_id: IdLike, subject_key: str) -> Optional[IntegrationConnection]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"integration_id": self._to_object_id(integration_id), "subject_key": subject_key})
        except ValueError:
            return None

    async def get_by_id(self, connection_id: IdLike, project_id: IdLike) -> Optional[IntegrationConnection]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one(
                {"_id": self._to_object_id(connection_id), "project_id": self._to_object_id(project_id)}
            )
        except ValueError:
            return None

    async def list_by_integration(
        self, project_id: IdLike, integration_id: IdLike, skip: int = 0, limit: int = 50
    ) -> Tuple[List[IntegrationConnection], int]:
        if not self.is_db_ready():
            return [], 0
        query = {"project_id": self._to_object_id(project_id), "integration_id": self._to_object_id(integration_id)}
        total = await self.count(query)
        if total == 0:
            return [], 0
        return await self.find_many(query, skip=skip, limit=limit, sort=[("updated_at", DESCENDING)]), total

    async def list_for_subject(
        self, project_id: IdLike, subject_type: ConnectionSubjectType, subject_id: Optional[str]
    ) -> List[IntegrationConnection]:
        if not self.is_db_ready():
            return []
        query: Dict[str, Any] = {"project_id": self._to_object_id(project_id), "subject_type": subject_type.value}
        query["subject_id"] = subject_id
        return await self.find_many(query, limit=500)

    async def update_with_revision(
        self, connection_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> IntegrationConnection:
        return await occ_update(
            IntegrationConnection,
            self.get_collection(),
            {"_id": self._to_object_id(connection_id)},
            expected_revision,
            update_dict,
            label="Connection",
            deleted_flag_field=None,
        )

    async def set_status(self, connection_id: IdLike, status: ConnectionStatus, error: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc)
        update: Dict[str, Any] = {"status": status.value, "updated_at": now}
        if error is not None:
            update.update(last_error=error[:500], last_error_at=now)
        await self.get_collection().update_one({"_id": self._to_object_id(connection_id)}, {"$set": update})

    async def touch_used(self, connection_id: IdLike) -> None:
        await self.get_collection().update_one(
            {"_id": self._to_object_id(connection_id)}, {"$set": {"last_used_at": datetime.now(timezone.utc)}}
        )

    async def delete(self, connection_id: IdLike) -> bool:
        result = await self.get_collection().delete_one({"_id": self._to_object_id(connection_id)})
        return result.deleted_count > 0

    async def set_status_for_subject(
        self,
        project_id: IdLike,
        subject_type: ConnectionSubjectType,
        subject_id: str,
        from_status: ConnectionStatus,
        to_status: ConnectionStatus,
    ) -> int:
        result = await self.get_collection().update_many(
            {
                "project_id": self._to_object_id(project_id),
                "subject_type": subject_type.value,
                "subject_id": subject_id,
                "status": from_status.value,
            },
            {"$set": {"status": to_status.value, "updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count

    async def delete_by_subject(self, project_id: IdLike, subject_type: ConnectionSubjectType, subject_id: str) -> int:
        result = await self.get_collection().delete_many(
            {"project_id": self._to_object_id(project_id), "subject_type": subject_type.value, "subject_id": subject_id}
        )
        return result.deleted_count

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class ConnectSessionRepository(BaseRepository[ConnectSession], IConnectSessionRepository):
    def __init__(self) -> None:
        super().__init__(ConnectSession)

    async def create(self, document: ConnectSession, session: Optional[Any] = None) -> ConnectSession:  # type: ignore[override]
        return await super().create(document, session=session)

    async def get_by_token_hash(self, token_hash: str) -> Optional[ConnectSession]:
        return await self.find_one({"token_hash": token_hash}) if self.is_db_ready() else None

    async def get_by_state_hash(self, state_hash: str) -> Optional[ConnectSession]:
        return await self.find_one({"state_hash": state_hash}) if self.is_db_ready() else None

    async def mark_started(
        self, session_id: IdLike, state_hash: str, verifier_envelope: EncryptedEnvelope
    ) -> Optional[ConnectSession]:
        result = await self.get_collection().find_one_and_update(
            {
                "_id": self._to_object_id(session_id),
                "status": ConnectSessionStatus.PENDING.value,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            },
            {
                "$set": serialize_for_mongo(
                    {
                        "status": ConnectSessionStatus.STARTED,
                        "state_hash": state_hash,
                        "pkce_verifier_envelope": verifier_envelope,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            },
            return_document=ReturnDocument.AFTER,
        )
        return _doc(ConnectSession, result) if result is not None else None

    async def finish(
        self, session_id: IdLike, status: ConnectSessionStatus, error: Optional[str] = None
    ) -> Optional[ConnectSession]:
        now = datetime.now(timezone.utc)
        result = await self.get_collection().find_one_and_update(
            {"_id": self._to_object_id(session_id), "status": ConnectSessionStatus.STARTED.value},
            {"$set": {"status": status.value, "error": error, "consumed_at": now, "updated_at": now}},
            return_document=ReturnDocument.AFTER,
        )
        return _doc(ConnectSession, result) if result is not None else None

    async def mark_failed(self, session_id: IdLike, error: str) -> None:
        now = datetime.now(timezone.utc)
        await self.get_collection().update_one(
            {"_id": self._to_object_id(session_id)},
            {"$set": {"status": ConnectSessionStatus.FAILED.value, "error": error[:300], "consumed_at": now, "updated_at": now}},
        )

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class OAuthClientRepository(BaseRepository[IntegrationOAuthClient], IOAuthClientRepository):
    def __init__(self) -> None:
        super().__init__(IntegrationOAuthClient)

    async def get_by_integration(self, integration_id: IdLike) -> Optional[IntegrationOAuthClient]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"integration_id": self._to_object_id(integration_id)})
        except ValueError:
            return None

    async def save(self, document: IntegrationOAuthClient) -> IntegrationOAuthClient:
        existing = await self.get_by_integration(document.integration_id)
        if existing is None:
            try:
                await document.insert()
                return document
            except DuplicateKeyError:
                existing = await self.get_by_integration(document.integration_id)
        replacement = serialize_for_mongo(document.model_dump(exclude={"id", "revision_id"}))
        replacement["revision"] = (existing.revision + 1) if existing else 1
        result = await self.get_collection().find_one_and_update(
            {"integration_id": document.integration_id}, {"$set": replacement}, return_document=ReturnDocument.AFTER
        )
        return _doc(IntegrationOAuthClient, result)

    async def delete_by_integration(self, integration_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"integration_id": self._to_object_id(integration_id)})
        return result.deleted_count

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


class ToolPolicyRepository(BaseRepository[ProjectToolPolicy], IToolPolicyRepository):
    def __init__(self) -> None:
        super().__init__(ProjectToolPolicy)

    async def get(self, project_id: IdLike) -> Optional[ProjectToolPolicy]:
        if not self.is_db_ready():
            return None
        try:
            return await self.find_one({"project_id": self._to_object_id(project_id)})
        except ValueError:
            return None

    async def get_or_create(self, project_id: IdLike) -> ProjectToolPolicy:
        existing = await self.get(project_id)
        if existing is not None:
            return existing
        document = ProjectToolPolicy(project_id=self._to_object_id(project_id))
        try:
            await document.insert()
            return document
        except DuplicateKeyError:
            winner = await self.get(project_id)
            if winner is None:
                raise
            return winner

    async def update_with_revision(
        self, project_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> ProjectToolPolicy:
        return await occ_update(
            ProjectToolPolicy,
            self.get_collection(),
            {"project_id": self._to_object_id(project_id)},
            expected_revision,
            update_dict,
            label="Tool policy",
            deleted_flag_field=None,
        )

    async def delete_by_project_id(self, project_id: IdLike) -> int:
        result = await self.get_collection().delete_many({"project_id": self._to_object_id(project_id)})
        return result.deleted_count


def get_connection_repository() -> ConnectionRepository:
    return ConnectionRepository()


def get_connect_session_repository() -> ConnectSessionRepository:
    return ConnectSessionRepository()


def get_oauth_client_repository() -> OAuthClientRepository:
    return OAuthClientRepository()


def get_tool_policy_repository() -> ToolPolicyRepository:
    return ToolPolicyRepository()
