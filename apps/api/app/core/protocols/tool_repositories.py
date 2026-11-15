"""
Repository protocols for Module 07 (SRS-07). One small protocol per aggregate
(Interface Segregation) so services depend only on the persistence they use.
"""
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union, runtime_checkable
from beanie import PydanticObjectId
from bson import ObjectId

from app.models.end_user import EndUserStatus, ProjectEndUser
from app.models.integration import Integration, IntegrationStatus, IntegrationType
from app.models.tool import (
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
    ToolDefinition,
    ToolSetting,
    ToolSyncState,
)
from app.models.tool_invocation import InvocationStatus, ToolInvocation

IdLike = Union[str, PydanticObjectId, ObjectId]


@runtime_checkable
class IIntegrationRepository(Protocol):
    async def create(self, document: Integration, session: Optional[Any] = None) -> Integration: ...

    async def get_by_id_and_project(
        self, integration_id: IdLike, project_id: IdLike, include_deleted: bool = False
    ) -> Optional[Integration]: ...

    async def get_by_slug(self, project_id: IdLike, slug: str) -> Optional[Integration]: ...

    async def list_by_project(
        self,
        project_id: IdLike,
        type: Optional[IntegrationType] = None,
        status: Optional[IntegrationStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[Integration], int]: ...

    async def update_with_revision(
        self,
        integration_id: IdLike,
        project_id: IdLike,
        expected_revision: int,
        update_dict: Dict[str, Any],
        include_deleted: bool = False,
    ) -> Integration: ...

    async def update_runtime_state(
        self, integration_id: IdLike, project_id: IdLike, update_dict: Dict[str, Any]
    ) -> None: ...

    async def find_referencing_secret(self, project_id: IdLike, secret_id: IdLike) -> List[Integration]: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IToolDefinitionRepository(Protocol):
    async def create_many(self, documents: List[ToolDefinition]) -> List[ToolDefinition]: ...

    async def get_by_key(self, project_id: IdLike, tool_key: str) -> Optional[ToolDefinition]: ...

    async def list_by_integration(self, integration_id: IdLike) -> List[ToolDefinition]: ...

    async def list_by_keys(self, project_id: IdLike, tool_keys: List[str]) -> List[ToolDefinition]: ...

    async def list_by_project(
        self,
        project_id: IdLike,
        integration_id: Optional[IdLike] = None,
        sync_state: Optional[ToolSyncState] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ToolDefinition], int]: ...

    async def update_definition(
        self, tool_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> ToolDefinition: ...

    async def set_sync_state(self, tool_ids: List[IdLike], state: ToolSyncState) -> int: ...

    async def delete_by_integration(self, integration_id: IdLike) -> int: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IToolSettingRepository(Protocol):
    async def get_by_key(self, project_id: IdLike, tool_key: str) -> Optional[ToolSetting]: ...

    async def list_by_keys(self, project_id: IdLike, tool_keys: List[str]) -> List[ToolSetting]: ...

    async def get_or_create_default(
        self, project_id: IdLike, tool_key: str, defaults: Dict[str, Any]
    ) -> ToolSetting: ...

    async def update_with_revision(
        self, project_id: IdLike, tool_key: str, expected_revision: int, update_dict: Dict[str, Any]
    ) -> ToolSetting: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IToolBindingRepository(Protocol):
    async def list_by_project(
        self,
        project_id: IdLike,
        subject_type: Optional[BindingSubjectType] = None,
        subject_id: Optional[str] = None,
    ) -> List[ToolBinding]: ...

    async def list_for_resolution(
        self, project_id: IdLike, agent_id: Optional[str], end_user_id: Optional[str]
    ) -> List[ToolBinding]: ...

    async def replace_for_subject(
        self,
        project_id: IdLike,
        subject_type: BindingSubjectType,
        subject_id: Optional[str],
        bindings: List[ToolBinding],
    ) -> List[ToolBinding]: ...

    async def delete_by_target(self, project_id: IdLike, target_type: BindingTargetType, target_id: str) -> int: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IEndUserRepository(Protocol):
    async def upsert_seen(
        self,
        project_id: IdLike,
        external_id: str,
        display_name: Optional[str],
        email: Optional[str],
        attributes: Optional[Dict[str, str]],
    ) -> Tuple[ProjectEndUser, bool]: ...

    async def get_by_external_id(self, project_id: IdLike, external_id: str) -> Optional[ProjectEndUser]: ...

    async def get_by_id_and_project(self, end_user_id: IdLike, project_id: IdLike) -> Optional[ProjectEndUser]: ...

    async def list_by_project(
        self,
        project_id: IdLike,
        status: Optional[EndUserStatus] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectEndUser], int]: ...

    async def update_status(self, project_id: IdLike, external_id: str, status: EndUserStatus) -> ProjectEndUser: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IToolInvocationRepository(Protocol):
    async def create(self, document: ToolInvocation) -> ToolInvocation: ...

    async def list_by_project(
        self,
        project_id: IdLike,
        tool_key: Optional[str] = None,
        status: Optional[InvocationStatus] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ToolInvocation], int]: ...

    async def scrub_subject(self, project_id: IdLike, subject_id: str) -> int: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


# ---------------------------------------------------------------------------------------------
# Phase 2: connections, connect sessions, OAuth clients, tool policy
# ---------------------------------------------------------------------------------------------
from datetime import datetime  # noqa: E402

from app.core.crypto.envelope import EncryptedEnvelope  # noqa: E402
from app.models.connection import (  # noqa: E402
    ConnectionStatus,
    ConnectionSubjectType,
    ConnectSession,
    ConnectSessionStatus,
    CredentialKind,
    IntegrationConnection,
    IntegrationOAuthClient,
    ProjectToolPolicy,
)


@runtime_checkable
class IConnectionRepository(Protocol):
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
    ) -> IntegrationConnection: ...

    async def get(self, integration_id: IdLike, subject_key: str) -> Optional[IntegrationConnection]: ...

    async def get_by_id(self, connection_id: IdLike, project_id: IdLike) -> Optional[IntegrationConnection]: ...

    async def list_by_integration(
        self, project_id: IdLike, integration_id: IdLike, skip: int = 0, limit: int = 50
    ) -> Tuple[List[IntegrationConnection], int]: ...

    async def list_for_subject(
        self, project_id: IdLike, subject_type: ConnectionSubjectType, subject_id: Optional[str]
    ) -> List[IntegrationConnection]: ...

    async def update_with_revision(
        self, connection_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> IntegrationConnection: ...

    async def set_status(self, connection_id: IdLike, status: ConnectionStatus, error: Optional[str] = None) -> None: ...

    async def touch_used(self, connection_id: IdLike) -> None: ...

    async def delete(self, connection_id: IdLike) -> bool: ...

    async def set_status_for_subject(
        self,
        project_id: IdLike,
        subject_type: ConnectionSubjectType,
        subject_id: str,
        from_status: ConnectionStatus,
        to_status: ConnectionStatus,
    ) -> int: ...

    async def delete_by_subject(self, project_id: IdLike, subject_type: ConnectionSubjectType, subject_id: str) -> int: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IConnectSessionRepository(Protocol):
    async def create(self, document: ConnectSession) -> ConnectSession: ...

    async def get_by_token_hash(self, token_hash: str) -> Optional[ConnectSession]: ...

    async def get_by_state_hash(self, state_hash: str) -> Optional[ConnectSession]: ...

    async def mark_started(
        self, session_id: IdLike, state_hash: str, verifier_envelope: EncryptedEnvelope
    ) -> Optional[ConnectSession]:
        """Atomically move ``pending`` -> ``started``; ``None`` if it was already used."""
        ...

    async def finish(
        self, session_id: IdLike, status: ConnectSessionStatus, error: Optional[str] = None
    ) -> Optional[ConnectSession]:
        """Atomically move ``started`` -> ``completed``/``failed``; ``None`` if not in ``started`` (single use)."""
        ...

    async def mark_failed(self, session_id: IdLike, error: str) -> None: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IOAuthClientRepository(Protocol):
    async def get_by_integration(self, integration_id: IdLike) -> Optional[IntegrationOAuthClient]: ...

    async def save(self, document: IntegrationOAuthClient) -> IntegrationOAuthClient: ...

    async def delete_by_integration(self, integration_id: IdLike) -> int: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


@runtime_checkable
class IToolPolicyRepository(Protocol):
    async def get(self, project_id: IdLike) -> Optional[ProjectToolPolicy]: ...

    async def get_or_create(self, project_id: IdLike) -> ProjectToolPolicy: ...

    async def update_with_revision(
        self, project_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> ProjectToolPolicy: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...


# ---------------------------------------------------------------------------------------------
# MCP App resources
# ---------------------------------------------------------------------------------------------
from app.models.app_resource import AppResource  # noqa: E402


@runtime_checkable
class IAppResourceRepository(Protocol):
    async def get_by_id_and_project(self, resource_id: IdLike, project_id: IdLike) -> Optional[AppResource]: ...

    async def get_by_uri(self, integration_id: IdLike, uri: str) -> Optional[AppResource]: ...

    async def list_by_integration(self, project_id: IdLike, integration_id: IdLike) -> List[AppResource]: ...

    async def save(self, document: AppResource) -> AppResource: ...

    async def update_with_revision(
        self, resource_id: IdLike, expected_revision: int, update_dict: Dict[str, Any]
    ) -> AppResource: ...

    async def delete_by_project_id(self, project_id: IdLike) -> int: ...
