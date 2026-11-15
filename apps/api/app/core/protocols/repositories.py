from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union, runtime_checkable
from beanie import PydanticObjectId
from bson import ObjectId

from app.models.credential import CredentialStatus, ProjectCredential
from app.models.project import Project, ProjectAuditAction, ProjectAuditLog, ProjectMember, ProjectRole, ProjectStatus
from app.models.secret import ProjectSecret


@runtime_checkable
class IProjectRepository(Protocol):
    """Protocol defining the interface for Project persistence operations."""

    async def get_by_id(self, id: Union[str, PydanticObjectId, ObjectId]) -> Optional[Project]:
        ...

    async def get_by_slug(self, slug: str) -> Optional[Project]:
        ...

    async def get_by_id_or_slug(self, identifier: Union[str, PydanticObjectId, ObjectId]) -> Optional[Project]:
        ...

    async def list_by_ids(
        self,
        project_ids: List[Union[PydanticObjectId, ObjectId, str]],
        status: Optional[ProjectStatus] = None,
        statuses: Optional[List[ProjectStatus]] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Project], int]:
        ...

    async def create(self, document: Project, session: Optional[Any] = None) -> Project:
        ...

    async def update_with_version(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_version: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> Project:
        ...

    async def transition_status(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        target_status: ProjectStatus,
        expected_version: int,
        session: Optional[Any] = None,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Project:
        ...

    async def soft_delete(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        retention_days: int = 30,
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def purge(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        ...


@runtime_checkable
class ICredentialRepository(Protocol):
    """Protocol defining the interface for ProjectCredential persistence operations."""

    async def create(
        self,
        document: ProjectCredential,
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        ...

    async def get_by_hash(self, key_hash: str) -> Optional[ProjectCredential]:
        ...

    async def get_by_id_and_project(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectCredential]:
        ...

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
        ...

    async def update_with_revision(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectCredential:
        ...

    async def record_usage_debounced(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        client_ip: Optional[str] = None,
        current_last_used: Optional[datetime] = None,
        debounce_seconds: int = 300,
    ) -> bool:
        ...

    async def soft_delete(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def purge(
        self,
        credential_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        ...


@runtime_checkable
class ISecretRepository(Protocol):
    """Protocol defining the interface for ProjectSecret persistence operations."""

    async def create(self, document: ProjectSecret, session: Optional[Any] = None) -> ProjectSecret:
        ...

    async def check_exists(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: str,
        name: str,
    ) -> bool:
        ...

    async def get_by_id_and_project(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        include_deleted: bool = False,
    ) -> Optional[ProjectSecret]:
        ...

    async def get_by_project_environment_name(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: str,
        name: str,
        include_deleted: bool = False,
    ) -> Optional[ProjectSecret]:
        ...

    async def list_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        environment: Optional[str] = None,
        is_system: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
        include_deleted: bool = False,
    ) -> Tuple[List[ProjectSecret], int]:
        ...

    async def update_with_revision(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        expected_revision: int,
        update_dict: Dict[str, Any],
        session: Optional[Any] = None,
    ) -> ProjectSecret:
        ...

    async def soft_delete(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def purge(
        self,
        secret_id: Union[str, PydanticObjectId, ObjectId],
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        ...


@runtime_checkable
class IProjectAuditRepository(Protocol):
    """Protocol defining the interface for ProjectAuditLog persistence operations."""

    async def create_log(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        action: ProjectAuditAction,
        target_user_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        session: Optional[Any] = None,
    ) -> ProjectAuditLog:
        ...

    async def list_events(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        action: Optional[Union[ProjectAuditAction, str]] = None,
        actor_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectAuditLog], int]:
        ...

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        ...


@runtime_checkable
class IProjectMemberRepository(Protocol):
    """Protocol defining the interface for ProjectMember persistence operations."""

    async def add_member(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        role: ProjectRole,
        invited_by: Optional[str] = None,
        session: Optional[Any] = None,
    ) -> ProjectMember:
        ...

    async def get_membership(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
    ) -> Optional[ProjectMember]:
        ...

    async def list_members(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        role: Optional[ProjectRole] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectMember], int]:
        ...

    async def update_role(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        new_role: ProjectRole,
        session: Optional[Any] = None,
    ) -> Optional[ProjectMember]:
        ...

    async def remove_member(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
        session: Optional[Any] = None,
    ) -> bool:
        ...

    async def count_by_role(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        role: ProjectRole,
    ) -> int:
        ...

    async def count_members(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
    ) -> int:
        ...

    async def purge_by_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        ...
