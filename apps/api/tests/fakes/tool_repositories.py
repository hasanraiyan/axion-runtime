"""
In-memory fakes for the Module 07 repositories (and the project/secret/audit collaborators).
They honour the unique indexes, soft deletion, and OCC rules of the real repositories so
service tests exercise real behaviour without MongoDB.
"""
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from beanie import PydanticObjectId

from app.core.exceptions import (
    ConflictError,
    DuplicateIntegrationNameError,
    DuplicateIntegrationSlugError,
    NotFoundError,
    RevisionConflictError,
)
from app.models.end_user import EndUserStatus, ProjectEndUser
from app.models.integration import Integration, IntegrationHealth
from app.models.project import Project, ProjectStatus
from app.models.tool import ToolBinding, ToolDefinition, ToolSetting
from app.models.tool_invocation import ToolInvocation


def _s(value: Any) -> str:
    return str(value)


def _new_id(doc: Any) -> None:
    if getattr(doc, "id", None) is None:
        doc.id = PydanticObjectId()


class FakeProjectRepository:
    def __init__(self) -> None:
        self.projects: Dict[str, Project] = {}

    def add(self, project: Project) -> Project:
        _new_id(project)
        self.projects[_s(project.id)] = project
        return project

    async def get_by_id_or_slug(self, identifier: Any) -> Optional[Project]:
        key = _s(identifier)
        if key in self.projects:
            return self.projects[key]
        return next((p for p in self.projects.values() if p.slug == key), None)

    async def get_by_id(self, identifier: Any) -> Optional[Project]:
        return self.projects.get(_s(identifier))


class FakeSecretRepository:
    def __init__(self) -> None:
        self.secrets: Dict[str, Any] = {}

    def add(self, project_id: Any, name: str, environment: str = "production", is_deleted: bool = False) -> Any:
        secret = SimpleNamespace(
            id=PydanticObjectId(),
            project_id=project_id,
            name=name,
            environment=environment,
            is_deleted=is_deleted,
            envelope={"fake": True},
        )
        self.secrets[_s(secret.id)] = secret
        return secret

    async def get_by_id_and_project(self, secret_id: Any, project_id: Any, include_deleted: bool = False) -> Optional[Any]:
        secret = self.secrets.get(_s(secret_id))
        if secret is None or _s(secret.project_id) != _s(project_id):
            return None
        if secret.is_deleted and not include_deleted:
            return None
        return secret

    async def find_by_names(self, project_id: Any, environment: str, names: List[str], include_deleted: bool = False) -> List[Any]:
        return [
            s
            for s in self.secrets.values()
            if _s(s.project_id) == _s(project_id)
            and s.environment == environment
            and s.name in names
            and (include_deleted or not s.is_deleted)
        ]


class FakeCrypto:
    """
    MOD-02 project secrets decrypt to ``plain:<name>`` so tests can assert the credential reached the wire.
    Everything else (connection tokens) goes through the REAL AES-256-GCM envelope service, so AAD binding
    to (project, integration, subject) is genuinely exercised.
    """

    def __init__(self) -> None:
        from app.core.crypto import CryptoService

        self._real = CryptoService()

    async def decrypt_secret(self, envelope: Any, project_id: str, environment: str, name: str) -> str:
        if isinstance(envelope, dict) and envelope.get("fake"):
            return f"plain:{name}"
        return await self._real.decrypt_secret(envelope, project_id, environment, name)

    async def encrypt_secret(self, plaintext: Any, project_id: str, environment: str, name: str) -> Any:
        return await self._real.encrypt_secret(plaintext, project_id, environment, name)


class FakeAuditRepository:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def log_event(self, project_id: Any, actor_id: str, action: Any, payload: Dict[str, Any], **_: Any) -> None:
        self.events.append({"project_id": _s(project_id), "actor_id": actor_id, "action": getattr(action, "value", action), "payload": payload})

    def actions(self) -> List[str]:
        return [e["action"] for e in self.events]


class FakeIntegrationRepository:
    def __init__(self) -> None:
        self.items: Dict[str, Integration] = {}

    async def create(self, document: Integration, session: Any = None) -> Integration:
        for other in self.items.values():
            if _s(other.project_id) == _s(document.project_id):
                if other.slug == document.slug:
                    raise DuplicateIntegrationSlugError(document.slug)
                if not other.is_deleted and other.name == document.name:
                    raise DuplicateIntegrationNameError(document.name)
        _new_id(document)
        self.items[_s(document.id)] = document.model_copy(deep=True)
        return document

    async def get_by_id_and_project(self, integration_id: Any, project_id: Any, include_deleted: bool = False) -> Optional[Integration]:
        doc = self.items.get(_s(integration_id))
        if doc is None or _s(doc.project_id) != _s(project_id) or (doc.is_deleted and not include_deleted):
            return None
        return doc.model_copy(deep=True)

    async def get_by_slug(self, project_id: Any, slug: str) -> Optional[Integration]:
        return next((d.model_copy(deep=True) for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.slug == slug), None)

    async def list_by_project(
        self, project_id: Any, type: Any = None, status: Any = None, search: Optional[str] = None,
        skip: int = 0, limit: int = 50, include_deleted: bool = False,
    ) -> Tuple[List[Integration], int]:
        rows = [d for d in self.items.values() if _s(d.project_id) == _s(project_id) and (include_deleted or not d.is_deleted)]
        if type is not None:
            rows = [d for d in rows if d.type == type]
        if status is not None:
            rows = [d for d in rows if d.status == status]
        if search:
            rows = [d for d in rows if search.lower() in d.name.lower() or search.lower() in d.slug]
        return [d.model_copy(deep=True) for d in rows[skip : skip + limit]], len(rows)

    async def update_with_revision(
        self, integration_id: Any, project_id: Any, expected_revision: int, update_dict: Dict[str, Any], include_deleted: bool = False
    ) -> Integration:
        doc = self.items.get(_s(integration_id))
        if doc is None or _s(doc.project_id) != _s(project_id):
            raise NotFoundError("Integration not found")
        if doc.is_deleted and not include_deleted:
            raise ConflictError("Integration has been deleted")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        new_name = update_dict.get("name")
        if new_name:
            for other in self.items.values():
                if other.id != doc.id and _s(other.project_id) == _s(project_id) and not other.is_deleted and other.name == new_name:
                    raise DuplicateIntegrationNameError(new_name)
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        doc.updated_at = datetime.now(timezone.utc)
        return doc.model_copy(deep=True)

    async def update_runtime_state(self, integration_id: Any, project_id: Any, update_dict: Dict[str, Any]) -> None:
        doc = self.items.get(_s(integration_id))
        if doc is not None:
            for key, value in update_dict.items():
                if key == "health" and isinstance(value, dict):
                    value = IntegrationHealth(**value)  # MongoDB re-validates nested documents on load
                setattr(doc, key, value)

    async def find_referencing_secret(self, project_id: Any, secret_id: Any) -> List[Integration]:
        return [
            d.model_copy(deep=True)
            for d in self.items.values()
            if _s(d.project_id) == _s(project_id) and not d.is_deleted and secret_id in d.referenced_secret_ids
        ]

    async def delete_by_project_id(self, project_id: Any) -> int:
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeToolDefinitionRepository:
    def __init__(self) -> None:
        self.items: Dict[str, ToolDefinition] = {}

    async def create_many(self, documents: List[ToolDefinition]) -> List[ToolDefinition]:
        for doc in documents:
            if any(_s(d.project_id) == _s(doc.project_id) and d.tool_key == doc.tool_key for d in self.items.values()):
                raise ConflictError("duplicate tool_key")
            _new_id(doc)
            self.items[_s(doc.id)] = doc.model_copy(deep=True)
        return documents

    async def get_by_key(self, project_id: Any, tool_key: str) -> Optional[ToolDefinition]:
        return next(
            (d.model_copy(deep=True) for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.tool_key == tool_key), None
        )

    async def list_by_integration(self, integration_id: Any) -> List[ToolDefinition]:
        return [d.model_copy(deep=True) for d in self.items.values() if _s(d.integration_id) == _s(integration_id)]

    async def list_by_keys(self, project_id: Any, tool_keys: List[str]) -> List[ToolDefinition]:
        return [d.model_copy(deep=True) for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.tool_key in tool_keys]

    async def list_by_project(
        self, project_id: Any, integration_id: Any = None, sync_state: Any = None, search: Optional[str] = None, skip: int = 0, limit: int = 50
    ) -> Tuple[List[ToolDefinition], int]:
        rows = [d for d in self.items.values() if _s(d.project_id) == _s(project_id)]
        if integration_id is not None:
            rows = [d for d in rows if _s(d.integration_id) == _s(integration_id)]
        if sync_state is not None:
            rows = [d for d in rows if d.sync_state == sync_state]
        if search:
            rows = [d for d in rows if search.lower() in d.tool_key or search.lower() in d.description.lower()]
        rows.sort(key=lambda d: d.tool_key)
        return [d.model_copy(deep=True) for d in rows[skip : skip + limit]], len(rows)

    async def update_definition(self, tool_id: Any, expected_revision: int, update_dict: Dict[str, Any]) -> ToolDefinition:
        doc = self.items.get(_s(tool_id))
        if doc is None:
            raise NotFoundError("Tool not found")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def set_sync_state(self, tool_ids: List[Any], state: Any) -> int:
        count = 0
        for tid in tool_ids:
            doc = self.items.get(_s(tid))
            if doc is not None:
                doc.sync_state = state
                count += 1
        return count

    async def delete_by_integration(self, integration_id: Any) -> int:
        keys = [k for k, d in self.items.items() if _s(d.integration_id) == _s(integration_id)]
        for k in keys:
            del self.items[k]
        return len(keys)

    async def delete_by_project_id(self, project_id: Any) -> int:
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeToolSettingRepository:
    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], ToolSetting] = {}

    async def get_by_key(self, project_id: Any, tool_key: str) -> Optional[ToolSetting]:
        doc = self.items.get((_s(project_id), tool_key))
        return doc.model_copy(deep=True) if doc else None

    async def list_by_keys(self, project_id: Any, tool_keys: List[str]) -> List[ToolSetting]:
        return [d.model_copy(deep=True) for (pid, key), d in self.items.items() if pid == _s(project_id) and key in tool_keys]

    async def get_or_create_default(self, project_id: Any, tool_key: str, defaults: Dict[str, Any]) -> ToolSetting:
        existing = await self.get_by_key(project_id, tool_key)
        if existing:
            return existing
        doc = ToolSetting(project_id=project_id, tool_key=tool_key, **defaults)
        _new_id(doc)
        self.items[(_s(project_id), tool_key)] = doc
        return doc.model_copy(deep=True)

    async def update_with_revision(self, project_id: Any, tool_key: str, expected_revision: int, update_dict: Dict[str, Any]) -> ToolSetting:
        doc = self.items.get((_s(project_id), tool_key))
        if doc is None:
            raise NotFoundError("Tool setting not found")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def delete_by_project_id(self, project_id: Any) -> int:
        keys = [k for k in self.items if k[0] == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeToolBindingRepository:
    def __init__(self) -> None:
        self.items: List[ToolBinding] = []

    async def list_by_project(self, project_id: Any, subject_type: Any = None, subject_id: Optional[str] = None) -> List[ToolBinding]:
        rows = [b for b in self.items if _s(b.project_id) == _s(project_id)]
        if subject_type is not None:
            rows = [b for b in rows if b.subject_type == subject_type]
        if subject_id is not None:
            rows = [b for b in rows if b.subject_id == subject_id]
        return [b.model_copy(deep=True) for b in rows]

    async def list_for_resolution(self, project_id: Any, agent_id: Optional[str], end_user_id: Optional[str]) -> List[ToolBinding]:
        out = []
        for b in self.items:
            if _s(b.project_id) != _s(project_id):
                continue
            if b.subject_type.value == "project_default":
                out.append(b)
            elif b.subject_type.value == "agent" and agent_id and b.subject_id == agent_id:
                out.append(b)
            elif b.subject_type.value == "end_user" and end_user_id and b.subject_id == end_user_id:
                out.append(b)
        return [b.model_copy(deep=True) for b in out]

    async def replace_for_subject(self, project_id: Any, subject_type: Any, subject_id: Optional[str], bindings: List[ToolBinding]) -> List[ToolBinding]:
        self.items = [
            b for b in self.items
            if not (_s(b.project_id) == _s(project_id) and b.subject_type == subject_type and b.subject_id == subject_id)
        ]
        for b in bindings:
            _new_id(b)
            self.items.append(b.model_copy(deep=True))
        return await self.list_by_project(project_id, subject_type, subject_id)

    async def delete_by_target(self, project_id: Any, target_type: Any, target_id: str) -> int:
        before = len(self.items)
        self.items = [b for b in self.items if not (_s(b.project_id) == _s(project_id) and b.target_type == target_type and b.target_id == target_id)]
        return before - len(self.items)

    async def delete_by_project_id(self, project_id: Any) -> int:
        before = len(self.items)
        self.items = [b for b in self.items if _s(b.project_id) != _s(project_id)]
        return before - len(self.items)


class FakeEndUserRepository:
    def __init__(self) -> None:
        self.items: Dict[str, ProjectEndUser] = {}

    async def upsert_seen(self, project_id: Any, external_id: str, display_name: Optional[str], email: Optional[str], attributes: Optional[Dict[str, str]]) -> Tuple[ProjectEndUser, bool]:
        existing = await self.get_by_external_id(project_id, external_id)
        if existing is None:
            doc = ProjectEndUser(project_id=project_id, external_id=external_id, display_name=display_name, email=email, attributes=attributes or {})
            _new_id(doc)
            self.items[_s(doc.id)] = doc
            return doc.model_copy(deep=True), True
        stored = self.items[_s(existing.id)]
        stored.last_seen_at = datetime.now(timezone.utc)
        if display_name is not None:
            stored.display_name = display_name
        if email is not None:
            stored.email = email
        if attributes is not None:
            stored.attributes = attributes
        return stored.model_copy(deep=True), False

    async def get_by_external_id(self, project_id: Any, external_id: str) -> Optional[ProjectEndUser]:
        return next(
            (d.model_copy(deep=True) for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.external_id == external_id), None
        )

    async def get_by_id_and_project(self, end_user_id: Any, project_id: Any) -> Optional[ProjectEndUser]:
        doc = self.items.get(_s(end_user_id))
        return doc.model_copy(deep=True) if doc and _s(doc.project_id) == _s(project_id) else None

    async def list_by_project(self, project_id: Any, status: Any = None, search: Optional[str] = None, skip: int = 0, limit: int = 50) -> Tuple[List[ProjectEndUser], int]:
        rows = [d for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.status != EndUserStatus.DELETED]
        if status is not None:
            rows = [d for d in rows if d.status == status]
        if search:
            rows = [d for d in rows if search.lower() in d.external_id.lower()]
        return [d.model_copy(deep=True) for d in rows[skip : skip + limit]], len(rows)

    async def update_status(self, project_id: Any, external_id: str, status: EndUserStatus) -> ProjectEndUser:
        doc = next((d for d in self.items.values() if _s(d.project_id) == _s(project_id) and d.external_id == external_id), None)
        if doc is None:
            raise NotFoundError("End user not found")
        doc.status = status
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def delete_by_project_id(self, project_id: Any) -> int:
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeToolInvocationRepository:
    def __init__(self) -> None:
        self.items: List[ToolInvocation] = []

    async def create(self, document: ToolInvocation) -> ToolInvocation:
        _new_id(document)
        self.items.append(document.model_copy(deep=True))
        return document

    async def list_by_project(self, project_id: Any, tool_key: Optional[str] = None, status: Any = None, skip: int = 0, limit: int = 50) -> Tuple[List[ToolInvocation], int]:
        rows = [d for d in self.items if _s(d.project_id) == _s(project_id)]
        if tool_key:
            rows = [d for d in rows if d.tool_key == tool_key]
        if status is not None:
            rows = [d for d in rows if d.status == status]
        return rows[skip : skip + limit], len(rows)

    async def scrub_subject(self, project_id: Any, subject_id: str) -> int:
        count = 0
        for d in self.items:
            if _s(d.project_id) == _s(project_id) and d.subject.get("id") == subject_id:
                d.subject = {"type": "end_user", "id": None, "erased": True}
                d.arguments_redacted = {}
                d.result_summary.pop("content", None)
                d.result_summary.pop("structured", None)
                count += 1
        return count

    async def delete_by_project_id(self, project_id: Any) -> int:
        before = len(self.items)
        self.items = [d for d in self.items if _s(d.project_id) != _s(project_id)]
        return before - len(self.items)


def make_project(status: ProjectStatus = ProjectStatus.ACTIVE, slug: str = "acme") -> Project:
    return Project(name="Acme", slug=slug, owner_id="user_owner", status=status)


# ----------------------------------------------------------------------------- phase 2 fakes
from app.models.connection import (  # noqa: E402
    ConnectionStatus,
    ConnectSession,
    ConnectSessionStatus,
    IntegrationConnection,
    IntegrationOAuthClient,
    ProjectToolPolicy,
)


class FakeConnectionRepository:
    def __init__(self) -> None:
        self.items: Dict[str, IntegrationConnection] = {}

    async def save_credentials(self, project_id, integration_id, subject_type, subject_id, subject_key, kind, access_envelope, refresh_envelope, expires_at, granted_scopes, external_account):
        existing = next((c for c in self.items.values() if _s(c.integration_id) == _s(integration_id) and c.subject_key == subject_key), None)
        if existing is None:
            doc = IntegrationConnection(
                project_id=project_id, integration_id=integration_id, subject_type=subject_type, subject_id=subject_id,
                subject_key=subject_key, credential_kind=kind, access_envelope=access_envelope, refresh_envelope=refresh_envelope,
                expires_at=expires_at, granted_scopes=granted_scopes, external_account=external_account,
            )
            _new_id(doc)
            self.items[_s(doc.id)] = doc
            return doc.model_copy(deep=True)
        existing.credential_kind, existing.access_envelope, existing.refresh_envelope = kind, access_envelope, refresh_envelope
        existing.expires_at, existing.granted_scopes, existing.external_account = expires_at, granted_scopes, external_account
        existing.status, existing.last_error = ConnectionStatus.ACTIVE, None
        existing.revision += 1
        return existing.model_copy(deep=True)

    async def get(self, integration_id, subject_key):
        doc = next((c for c in self.items.values() if _s(c.integration_id) == _s(integration_id) and c.subject_key == subject_key), None)
        return doc.model_copy(deep=True) if doc else None

    async def get_by_id(self, connection_id, project_id):
        doc = self.items.get(_s(connection_id))
        return doc.model_copy(deep=True) if doc and _s(doc.project_id) == _s(project_id) else None

    async def list_by_integration(self, project_id, integration_id, skip=0, limit=50):
        rows = [c for c in self.items.values() if _s(c.project_id) == _s(project_id) and _s(c.integration_id) == _s(integration_id)]
        return [c.model_copy(deep=True) for c in rows[skip : skip + limit]], len(rows)

    async def list_for_subject(self, project_id, subject_type, subject_id):
        return [
            c.model_copy(deep=True)
            for c in self.items.values()
            if _s(c.project_id) == _s(project_id) and c.subject_type == subject_type and c.subject_id == subject_id
        ]

    async def update_with_revision(self, connection_id, expected_revision, update_dict):
        doc = self.items.get(_s(connection_id))
        if doc is None:
            raise NotFoundError("Connection not found")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def set_status(self, connection_id, status, error=None):
        doc = self.items.get(_s(connection_id))
        if doc is not None:
            doc.status = status
            if error is not None:
                doc.last_error = error

    async def touch_used(self, connection_id):
        doc = self.items.get(_s(connection_id))
        if doc is not None:
            doc.last_used_at = datetime.now(timezone.utc)

    async def delete(self, connection_id):
        return self.items.pop(_s(connection_id), None) is not None

    async def set_status_for_subject(self, project_id, subject_type, subject_id, from_status, to_status):
        count = 0
        for c in self.items.values():
            if _s(c.project_id) == _s(project_id) and c.subject_type == subject_type and c.subject_id == subject_id and c.status == from_status:
                c.status = to_status
                count += 1
        return count

    async def delete_by_subject(self, project_id, subject_type, subject_id):
        keys = [k for k, c in self.items.items() if _s(c.project_id) == _s(project_id) and c.subject_type == subject_type and c.subject_id == subject_id]
        for k in keys:
            del self.items[k]
        return len(keys)

    async def delete_by_project_id(self, project_id):
        keys = [k for k, c in self.items.items() if _s(c.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeConnectSessionRepository:
    def __init__(self) -> None:
        self.items: Dict[str, ConnectSession] = {}

    async def create(self, document):
        _new_id(document)
        self.items[_s(document.id)] = document.model_copy(deep=True)
        return document

    async def get_by_token_hash(self, token_hash):
        doc = next((d for d in self.items.values() if d.token_hash == token_hash), None)
        return doc.model_copy(deep=True) if doc else None

    async def get_by_state_hash(self, state_hash):
        doc = next((d for d in self.items.values() if d.state_hash == state_hash), None)
        return doc.model_copy(deep=True) if doc else None

    async def mark_started(self, session_id, state_hash, verifier_envelope):
        doc = self.items.get(_s(session_id))
        expires = doc.expires_at if doc and doc.expires_at.tzinfo else (doc.expires_at.replace(tzinfo=timezone.utc) if doc else None)
        if doc is None or doc.status != ConnectSessionStatus.PENDING or expires <= datetime.now(timezone.utc):
            return None
        doc.status, doc.state_hash, doc.pkce_verifier_envelope = ConnectSessionStatus.STARTED, state_hash, verifier_envelope
        return doc.model_copy(deep=True)

    async def finish(self, session_id, status, error=None):
        doc = self.items.get(_s(session_id))
        if doc is None or doc.status != ConnectSessionStatus.STARTED:
            return None
        doc.status, doc.error, doc.consumed_at = status, error, datetime.now(timezone.utc)
        return doc.model_copy(deep=True)

    async def mark_failed(self, session_id, error):
        doc = self.items.get(_s(session_id))
        if doc is not None:
            doc.status, doc.error = ConnectSessionStatus.FAILED, error

    async def delete_by_project_id(self, project_id):
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeOAuthClientRepository:
    def __init__(self) -> None:
        self.items: Dict[str, IntegrationOAuthClient] = {}

    async def get_by_integration(self, integration_id):
        doc = self.items.get(_s(integration_id))
        return doc.model_copy(deep=True) if doc else None

    async def save(self, document):
        _new_id(document)
        self.items[_s(document.integration_id)] = document.model_copy(deep=True)
        return document

    async def delete_by_integration(self, integration_id):
        return 1 if self.items.pop(_s(integration_id), None) else 0

    async def delete_by_project_id(self, project_id):
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)


class FakeToolPolicyRepository:
    def __init__(self) -> None:
        self.items: Dict[str, ProjectToolPolicy] = {}

    async def get(self, project_id):
        doc = self.items.get(_s(project_id))
        return doc.model_copy(deep=True) if doc else None

    async def get_or_create(self, project_id):
        if _s(project_id) not in self.items:
            doc = ProjectToolPolicy(project_id=project_id)
            _new_id(doc)
            self.items[_s(project_id)] = doc
        return self.items[_s(project_id)].model_copy(deep=True)

    async def update_with_revision(self, project_id, expected_revision, update_dict):
        doc = self.items.get(_s(project_id))
        if doc is None:
            raise NotFoundError("Tool policy not found")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def delete_by_project_id(self, project_id):
        return 1 if self.items.pop(_s(project_id), None) else 0


from app.models.app_resource import AppResource  # noqa: E402


class FakeAppResourceRepository:
    def __init__(self) -> None:
        self.items: Dict[str, AppResource] = {}

    async def get_by_id_and_project(self, resource_id, project_id):
        doc = self.items.get(_s(resource_id))
        return doc.model_copy(deep=True) if doc and _s(doc.project_id) == _s(project_id) else None

    async def get_by_uri(self, integration_id, uri):
        doc = next((d for d in self.items.values() if _s(d.integration_id) == _s(integration_id) and d.uri == uri), None)
        return doc.model_copy(deep=True) if doc else None

    async def list_by_integration(self, project_id, integration_id):
        return [d.model_copy(deep=True) for d in self.items.values() if _s(d.project_id) == _s(project_id) and _s(d.integration_id) == _s(integration_id)]

    async def save(self, document):
        existing = next((d for d in self.items.values() if _s(d.integration_id) == _s(document.integration_id) and d.uri == document.uri), None)
        if existing is None:
            _new_id(document)
            self.items[_s(document.id)] = document.model_copy(deep=True)
            return document
        document.id, document.revision = existing.id, existing.revision + 1
        self.items[_s(existing.id)] = document.model_copy(deep=True)
        return document

    async def update_with_revision(self, resource_id, expected_revision, update_dict):
        doc = self.items.get(_s(resource_id))
        if doc is None:
            raise NotFoundError("App resource not found")
        if doc.revision != expected_revision:
            raise RevisionConflictError()
        for key, value in update_dict.items():
            setattr(doc, key, value)
        doc.revision += 1
        return doc.model_copy(deep=True)

    async def delete_by_project_id(self, project_id):
        keys = [k for k, d in self.items.items() if _s(d.project_id) == _s(project_id)]
        for k in keys:
            del self.items[k]
        return len(keys)
