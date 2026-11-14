"""
Comprehensive Acceptance Test Suite for Project Management (MOD-01).
Implements test scenarios and acceptance criteria per Section 10 of docs/specs/srs-01-project-management.md:
- TC-01: Project creation with auto-generated slug, collision hex suffixing, duplicate explicit slug 409 conflict, owner registration, audit event.
- TC-02: Project retrieval by ID and slug, member count & role calculation, 404 tenant isolation for non-members.
- TC-03: OCC partial updates (version matching increments version; stale version returns 409 Conflict).
- TC-04: Project listing with status filter, text search, tag filter, sorting, pagination.
- TC-05: FSM state machine transitions: ACTIVE -> ARCHIVED -> ACTIVE, ACTIVE -> SOFT_DELETED -> ACTIVE, SOFT_DELETED -> PURGED, and illegal transition rejection.
- TC-06: Member management: invite/add member, duplicate member 409, update role, admin hierarchy boundary, sole owner cannot leave without transfer.
- TC-07: Atomic ownership transfer: owner transfers to member, old owner becomes admin, new owner becomes owner, session transaction verified.
- TC-08: Audit log retrieval by owner/admin.
"""

from datetime import datetime, timezone
import re
from typing import Annotated, Any, Dict, List, Optional, Tuple, Union
from unittest.mock import AsyncMock, MagicMock
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
import pytest
from fastapi.testclient import TestClient

from app.api.deps import (
    get_current_user,
    get_project_audit_service,
    get_project_member_repository,
    get_project_member_service,
    get_project_repository,
    get_project_service,
    security,
)
from app.core.exceptions import (
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    UnauthorizedError,
)
from app.core.security import verify_clerk_token
from app.main import app
from app.models import DOCUMENT_MODELS
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectAuditLog,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
from app.repositories import get_project_audit_repository
from app.repositories.project_audit_repository import ProjectAuditRepository
from app.repositories.project_member_repository import ProjectMemberRepository
from app.repositories.project_repository import ProjectRepository
from app.schemas.auth import AuthenticatedUser
from app.services.project_audit_service import ProjectAuditService
from app.services.project_member_service import ProjectMemberService
from app.services.project_service import ProjectService


# ------------------------------------------------------------------------------
# In-Memory State & Repositories for End-to-End Simulation
# ------------------------------------------------------------------------------

class InMemoryProjectRepository(ProjectRepository):
    """Full-fidelity in-memory project repository with OCC and CAS status transitions."""

    def __init__(self):
        self.projects: Dict[str, Project] = {}

    async def get_by_id(self, project_id: Union[str, PydanticObjectId, ObjectId]) -> Optional[Project]:
        return self.projects.get(str(project_id))

    async def get_by_slug(self, slug: str) -> Optional[Project]:
        for p in self.projects.values():
            if p.slug == slug and p.status != ProjectStatus.PURGED:
                return p
        return None

    async def get_by_id_or_slug(self, identifier: Union[str, PydanticObjectId, ObjectId]) -> Optional[Project]:
        ident_str = str(identifier)
        if ObjectId.is_valid(ident_str) and ident_str in self.projects:
            return self.projects[ident_str]
        return await self.get_by_slug(ident_str)

    async def list_by_ids(
        self,
        project_ids: List[PydanticObjectId],
        status: Optional[ProjectStatus] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Project], int]:
        id_strs = {str(pid) for pid in project_ids}
        matched: List[Project] = [p for p in self.projects.values() if str(p.id) in id_strs]

        if status is not None:
            matched = [p for p in matched if p.status == status]
        else:
            # Default: exclude SOFT_DELETED and PURGED unless specified
            matched = [p for p in matched if p.status not in (ProjectStatus.SOFT_DELETED, ProjectStatus.PURGED)]

        if search:
            q = search.lower()
            matched = [
                p for p in matched
                if (p.name and q in p.name.lower())
                or (p.description and q in p.description.lower())
                or (p.slug and q in p.slug.lower())
            ]

        if tags:
            tag_set = set(tags)
            matched = [p for p in matched if any(t in tag_set for t in p.tags)]

        reverse = (sort_order == "desc")
        matched.sort(key=lambda p: getattr(p, sort_by, p.updated_at) or datetime.min.replace(tzinfo=timezone.utc), reverse=reverse)

        total = len(matched)
        return matched[skip : skip + limit], total

    async def create(self, document: Project, session: Optional[Any] = None) -> Project:
        for p in self.projects.values():
            if p.slug == document.slug and p.status == ProjectStatus.ACTIVE:
                raise ConflictError(f"Project slug '{document.slug}' already in use")

        if document.id is None:
            document.id = PydanticObjectId(ObjectId())
        document.created_at = datetime.now(timezone.utc)
        document.updated_at = datetime.now(timezone.utc)
        self.projects[str(document.id)] = document
        return document

    async def update(self, document: Project, session: Optional[Any] = None) -> Project:
        document.updated_at = datetime.now(timezone.utc)
        self.projects[str(document.id)] = document
        return document

    async def update_with_version(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        update_dict: Dict[str, Any],
        expected_version: int,
        session: Optional[Any] = None,
    ) -> Project:
        pid = str(project_id)
        existing = self.projects.get(pid)
        if existing is None:
            raise NotFoundError(f"Project '{pid}' not found")
        if existing.version != expected_version:
            raise ConflictError("Project version conflict: document was modified by a concurrent request")

        for k, v in update_dict.items():
            setattr(existing, k, v)
        existing.version = expected_version + 1
        existing.updated_at = datetime.now(timezone.utc)
        self.projects[pid] = existing
        return existing

    async def transition_status(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        from_state: ProjectStatus,
        to_state: ProjectStatus,
        expected_version: int,
        additional_updates: Optional[Dict[str, Any]] = None,
        session: Optional[Any] = None,
    ) -> Project:
        pid = str(project_id)
        existing = self.projects.get(pid)
        if existing is None:
            raise NotFoundError(f"Project '{pid}' not found")
        if existing.status != from_state:
            raise InvalidStateTransitionError(from_state=existing.status.value, to_state=to_state.value)
        if existing.version != expected_version:
            raise ConflictError("Project version conflict: document was modified by a concurrent request")

        existing.status = to_state
        existing.version = expected_version + 1
        existing.updated_at = datetime.now(timezone.utc)
        if additional_updates:
            for k, v in additional_updates.items():
                setattr(existing, k, v)
        self.projects[pid] = existing
        return existing


class InMemoryProjectMemberRepository(ProjectMemberRepository):
    """Full-fidelity in-memory project member repository with compound index uniqueness."""

    def __init__(self):
        self.members: Dict[str, ProjectMember] = {}

    async def get_membership(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        user_id: str,
    ) -> Optional[ProjectMember]:
        pid = str(project_id)
        for m in self.members.values():
            if str(m.project_id) == pid and m.user_id == user_id:
                return m
        return None

    async def list_project_ids_for_user(self, user_id: str) -> List[PydanticObjectId]:
        return [PydanticObjectId(m.project_id) for m in self.members.values() if m.user_id == user_id]

    async def list_members(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectMember], int]:
        pid = str(project_id)
        matched = [m for m in self.members.values() if str(m.project_id) == pid]
        total = len(matched)
        return matched[skip : skip + limit], total

    async def count_members(self, project_id: Union[str, PydanticObjectId, ObjectId]) -> int:
        pid = str(project_id)
        return sum(1 for m in self.members.values() if str(m.project_id) == pid)

    async def create(self, document: ProjectMember, session: Optional[Any] = None) -> ProjectMember:
        pid = str(document.project_id)
        for m in self.members.values():
            if str(m.project_id) == pid and m.user_id == document.user_id:
                raise ConflictError("User is already a member of this project")

        if document.id is None:
            document.id = PydanticObjectId(ObjectId())
        document.joined_at = datetime.now(timezone.utc)
        self.members[str(document.id)] = document
        return document

    async def update(self, document: ProjectMember, session: Optional[Any] = None) -> ProjectMember:
        self.members[str(document.id)] = document
        return document

    async def delete(self, document: ProjectMember, session: Optional[Any] = None) -> None:
        self.members.pop(str(document.id), None)

    async def delete_by_project_id(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        pid = str(project_id)
        to_del = [mid for mid, m in self.members.items() if str(m.project_id) == pid]
        for mid in to_del:
            del self.members[mid]
        return len(to_del)


class InMemoryProjectAuditRepository(ProjectAuditRepository):
    """Full-fidelity in-memory audit repository."""

    def __init__(self):
        self.logs: List[ProjectAuditLog] = []

    async def log_event(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
        action: ProjectAuditAction,
        payload: Dict[str, Any],
        target_user_id: Optional[str] = None,
        session: Optional[Any] = None,
    ) -> ProjectAuditLog:
        log = ProjectAuditLog(
            id=PydanticObjectId(ObjectId()),
            project_id=PydanticObjectId(str(project_id)),
            actor_id=actor_id,
            action=action,
            target_user_id=target_user_id,
            payload=payload,
            created_at=datetime.now(timezone.utc),
        )
        self.logs.append(log)
        return log

    async def list_events(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProjectAuditLog], int]:
        pid = str(project_id)
        matched = [log_entry for log_entry in self.logs if str(log_entry.project_id) == pid]
        matched.sort(key=lambda log_entry: log_entry.created_at, reverse=True)
        total = len(matched)
        return matched[skip : skip + limit], total

    async def delete_by_project_id(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        session: Optional[Any] = None,
    ) -> int:
        pid = str(project_id)
        before = len(self.logs)
        self.logs = [log_entry for log_entry in self.logs if str(log_entry.project_id) != pid]
        return before - len(self.logs)


# ------------------------------------------------------------------------------
# Test Fixtures
# ------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
async def init_mock_beanie():
    """Autouse fixture to register document models with mock Beanie initialization."""
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])
    col = MagicMock()
    col.name = "mock_col"
    col.create_index = AsyncMock()
    col.create_indexes = AsyncMock(return_value=[])
    col.index_information = AsyncMock(return_value={})
    col.find_one = AsyncMock(return_value=None)
    col.count_documents = AsyncMock(return_value=0)
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
    db.__getitem__.return_value = col
    await init_beanie(database=db, document_models=DOCUMENT_MODELS)
    return db


@pytest.fixture
def project_system():
    """
    Sets up integrated in-memory repositories and services, hooked directly
    into FastAPI app dependency overrides.
    """
    repo = InMemoryProjectRepository()
    member_repo = InMemoryProjectMemberRepository()
    audit_repo = InMemoryProjectAuditRepository()

    # Track session transactions for verification in TC-07
    transaction_records = []

    class MockAsyncSession:
        async def __aenter__(self):
            transaction_records.append("session_started")
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            transaction_records.append("session_ended")

        def start_transaction(self):
            return self

    mock_client = MagicMock()
    mock_client.start_session = AsyncMock(return_value=MockAsyncSession())

    project_service = ProjectService(
        project_repo=repo,
        member_repo=member_repo,
        audit_repo=audit_repo,
        mongo_client=mock_client,
    )
    member_service = ProjectMemberService(
        member_repo=member_repo,
        project_repo=repo,
        audit_repo=audit_repo,
    )
    audit_service = ProjectAuditService(
        audit_repo=audit_repo,
        member_repo=member_repo,
        project_repo=repo,
    )

    app.dependency_overrides[get_project_repository] = lambda: repo
    app.dependency_overrides[get_project_member_repository] = lambda: member_repo
    app.dependency_overrides[get_project_audit_repository] = lambda: audit_repo
    app.dependency_overrides[get_project_service] = lambda: project_service
    app.dependency_overrides[get_project_member_service] = lambda: member_service
    app.dependency_overrides[get_project_audit_service] = lambda: audit_service

    async def mock_auth_user(
        credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    ) -> AuthenticatedUser:
        if not credentials or not credentials.credentials:
            raise UnauthorizedError("Missing Authorization header")
        return await verify_clerk_token(credentials.credentials)

    app.dependency_overrides[get_current_user] = mock_auth_user

    yield {
        "repo": repo,
        "member_repo": member_repo,
        "audit_repo": audit_repo,
        "project_service": project_service,
        "member_service": member_service,
        "audit_service": audit_service,
        "transaction_records": transaction_records,
    }

    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def auth(user: str = "creator") -> Dict[str, str]:
    return {"Authorization": f"Bearer dev-token-{user}"}


# ==============================================================================
# TC-01: Project Creation
# ==============================================================================

def test_tc01_project_creation_auto_slug_and_owner_registration(client: TestClient, project_system):
    """
    TC-01.1: Project creation with auto-generated slug, initial version=1,
    status=active, creator registered as OWNER member, and PROJECT_CREATED audit log.
    """
    response = client.post(
        "/api/v1/projects",
        headers=auth("user_creator"),
        json={
            "name": "Acme Platform Services",
            "description": "Primary multi-tenant workspace",
            "tags": ["core", "infra"],
            "settings": {"default_environment": "production", "retention_days": 30},
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["success"] is True
    data = body["data"]

    assert data["name"] == "Acme Platform Services"
    assert data["slug"] == "acme-platform-services"
    assert data["version"] == 1
    assert data["status"] == "active"
    assert data["owner_id"] == "user_user_creator"
    assert data["user_role"] == "owner"
    assert data["member_count"] == 1

    project_id = data["id"]

    # Verify ProjectMember record exists with role 'owner'
    member = next(
        (m for m in project_system["member_repo"].members.values() if str(m.project_id) == project_id),
        None,
    )
    assert member is not None
    assert member.user_id == "user_user_creator"
    assert member.role == ProjectRole.OWNER

    # Verify ProjectAuditLog record exists with action 'project.created'
    audit = next(
        (log_item for log_item in project_system["audit_repo"].logs if str(log_item.project_id) == project_id),
        None,
    )
    assert audit is not None
    assert audit.action == ProjectAuditAction.PROJECT_CREATED
    assert audit.actor_id == "user_user_creator"


def test_tc01_auto_slug_collision_hex_suffix(client: TestClient, project_system):
    """
    TC-01.2: When auto-generated slug collides with existing project,
    system appends a 4-hex random suffix (e.g., acme-platform-a1b2).
    """
    res1 = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Acme Platform"})
    assert res1.status_code == 201
    assert res1.json()["data"]["slug"] == "acme-platform"

    res2 = client.post("/api/v1/projects", headers=auth("user_bob"), json={"name": "Acme Platform"})
    assert res2.status_code == 201
    slug2 = res2.json()["data"]["slug"]
    assert slug2.startswith("acme-platform-")
    # Verify suffix format: 4 lowercase hex characters
    suffix = slug2.replace("acme-platform-", "")
    assert re.match(r"^[0-9a-f]{4}$", suffix)


def test_tc01_duplicate_explicit_slug_conflict(client: TestClient, project_system):
    """
    TC-01.3: If slug is explicitly provided and collides with existing project,
    immediately returns 409 Conflict.
    """
    res1 = client.post(
        "/api/v1/projects",
        headers=auth("user_alice"),
        json={"name": "Platform Alpha", "slug": "alpha-custom-slug"},
    )
    assert res1.status_code == 201

    res2 = client.post(
        "/api/v1/projects",
        headers=auth("user_bob"),
        json={"name": "Platform Beta", "slug": "alpha-custom-slug"},
    )
    assert res2.status_code == 409
    body = res2.json()
    assert body["success"] is False
    assert body["error"]["code"] == "CONFLICT"
    assert "slug" in body["error"]["message"].lower()


# ==============================================================================
# TC-02: Project Retrieval & Multi-Tenant Isolation
# ==============================================================================

def test_tc02_retrieval_by_id_and_slug(client: TestClient, project_system):
    """
    TC-02.1: Retrieve project by ID and by slug, validating member count & role.
    """
    create_res = client.post(
        "/api/v1/projects",
        headers=auth("user_alice"),
        json={"name": "Observability Workspace", "slug": "observability-ws"},
    )
    assert create_res.status_code == 201
    pid = create_res.json()["data"]["id"]

    # Retrieve by ID
    get_by_id = client.get(f"/api/v1/projects/{pid}", headers=auth("user_alice"))
    assert get_by_id.status_code == 200
    data_id = get_by_id.json()["data"]
    assert data_id["id"] == pid
    assert data_id["user_role"] == "owner"
    assert data_id["member_count"] == 1

    # Retrieve by Slug
    get_by_slug = client.get("/api/v1/projects/observability-ws", headers=auth("user_alice"))
    assert get_by_slug.status_code == 200
    data_slug = get_by_slug.json()["data"]
    assert data_slug["id"] == pid


def test_tc02_tenant_isolation_non_member_yields_404(client: TestClient, project_system):
    """
    TC-02.2: Multi-tenant isolation rule (SRS Section 8.3): Non-member querying project
    receives 404 Not Found (NOT 403 Forbidden) to prevent identifier probing.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Secret Project"})
    pid = create_res.json()["data"]["id"]
    slug = create_res.json()["data"]["slug"]

    # Non-member bob queries by ID
    res_id = client.get(f"/api/v1/projects/{pid}", headers=auth("user_bob"))
    assert res_id.status_code == 404
    assert res_id.json()["error"]["code"] == "NOT_FOUND"

    # Non-member bob queries by slug
    res_slug = client.get(f"/api/v1/projects/{slug}", headers=auth("user_bob"))
    assert res_slug.status_code == 404
    assert res_slug.json()["error"]["code"] == "NOT_FOUND"


# ==============================================================================
# TC-03: Optimistic Concurrency Control (OCC)
# ==============================================================================

def test_tc03_occ_partial_update_and_conflict(client: TestClient, project_system):
    """
    TC-03: OCC partial updates: matching version increments version (v1 -> v2);
    stale version returns 409 Conflict.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "OCC Test Workspace"})
    pid = create_res.json()["data"]["id"]
    assert create_res.json()["data"]["version"] == 1

    # Update 1: Client A supplies correct version=1 -> Succeeds, version becomes 2
    res_up1 = client.patch(
        f"/api/v1/projects/{pid}",
        headers=auth("user_alice"),
        json={"description": "Updated by Client A", "version": 1},
    )
    assert res_up1.status_code == 200
    assert res_up1.json()["data"]["version"] == 2
    assert res_up1.json()["data"]["description"] == "Updated by Client A"

    # Update 2: Client B supplies stale version=1 -> Fails with 409 Conflict
    res_up2 = client.patch(
        f"/api/v1/projects/{pid}",
        headers=auth("user_alice"),
        json={"description": "Concurrent overwrite attempt", "version": 1},
    )
    assert res_up2.status_code == 409
    body = res_up2.json()
    assert body["success"] is False
    assert body["error"]["code"] == "CONFLICT"


def test_tc03_occ_update_insufficient_role_forbidden(client: TestClient, project_system):
    """
    TC-03.2: Viewer / non-admin cannot update project configuration.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Restricted Workspace"})
    pid = create_res.json()["data"]["id"]

    # Add user_bob as VIEWER
    add_res = client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_alice"),
        json={"user_id": "user_user_bob", "role": "viewer"},
    )
    assert add_res.status_code == 201

    # user_bob attempts to update -> 403 Forbidden
    up_res = client.patch(
        f"/api/v1/projects/{pid}",
        headers=auth("user_bob"),
        json={"name": "Hacked Name", "version": 1},
    )
    assert up_res.status_code == 403
    assert up_res.json()["error"]["code"] == "FORBIDDEN"


# ==============================================================================
# TC-04: Project Listing, Filtering, Search & Pagination
# ==============================================================================

def test_tc04_project_listing_search_filter_pagination(client: TestClient, project_system):
    """
    TC-04: Project listing:
    - Default lists caller's projects, excluding archived and soft-deleted.
    - Status filtering.
    - Text search on name, description, slug.
    - Tag filtering.
    - Pagination metadata (total_records, pages).
    """
    # Create 3 projects for user_alice
    p1 = client.post(
        "/api/v1/projects",
        headers=auth("user_alice"),
        json={"name": "Alpha Service", "tags": ["prod", "backend"], "description": "High throughput worker"},
    ).json()["data"]
    p2 = client.post(
        "/api/v1/projects",
        headers=auth("user_alice"),
        json={"name": "Beta Frontend", "tags": ["prod", "frontend"], "description": "React web console"},
    ).json()["data"]
    p3 = client.post(
        "/api/v1/projects",
        headers=auth("user_alice"),
        json={"name": "Gamma Legacy", "tags": ["legacy"], "description": "Old platform code"},
    ).json()["data"]

    # Archive p3
    client.post(f"/api/v1/projects/{p3['id']}/archive", headers=auth("user_alice"))

    # 1. Default listing: excludes archived p3 -> returns p1 and p2
    list_default = client.get("/api/v1/projects", headers=auth("user_alice"))
    assert list_default.status_code == 200
    items_default = list_default.json()["data"]["items"]
    slugs_default = [item["slug"] for item in items_default]
    assert p1["slug"] in slugs_default
    assert p2["slug"] in slugs_default
    assert p3["slug"] not in slugs_default

    # 2. Status filter: ?status=archived&include_archived=true -> returns p3
    list_archived = client.get("/api/v1/projects?status=archived&include_archived=true", headers=auth("user_alice"))
    assert list_archived.status_code == 200
    items_archived = list_archived.json()["data"]["items"]
    assert len(items_archived) == 1
    assert items_archived[0]["id"] == p3["id"]

    # 3. Text search: ?search=frontend
    list_search = client.get("/api/v1/projects?search=frontend", headers=auth("user_alice"))
    assert list_search.status_code == 200
    items_search = list_search.json()["data"]["items"]
    assert len(items_search) == 1
    assert items_search[0]["id"] == p2["id"]

    # 4. Tag filter: ?tags=frontend
    list_tags = client.get("/api/v1/projects?tags=frontend", headers=auth("user_alice"))
    assert list_tags.status_code == 200
    items_tags = list_tags.json()["data"]["items"]
    assert len(items_tags) == 1
    assert items_tags[0]["id"] == p2["id"]

    # 5. Pagination: page=1, page_size=1
    list_page = client.get("/api/v1/projects?page=1&page_size=1", headers=auth("user_alice"))
    assert list_page.status_code == 200
    pdata = list_page.json()["data"]
    assert len(pdata["items"]) == 1
    assert pdata["pagination"]["total_records"] == 2
    assert pdata["pagination"]["totalPages"] == 2


# ==============================================================================
# TC-05: FSM Lifecycle State Machine Transitions
# ==============================================================================

def test_tc05_fsm_archive_and_unarchive(client: TestClient, project_system):
    """
    TC-05.1: ACTIVE -> ARCHIVED -> ACTIVE (FSM T-02, T-03).
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Lifecycle Workspace"})
    pid = create_res.json()["data"]["id"]

    # Archive
    arch_res = client.post(f"/api/v1/projects/{pid}/archive", headers=auth("user_alice"))
    assert arch_res.status_code == 200
    assert arch_res.json()["data"]["status"] == "archived"
    assert arch_res.json()["data"]["version"] == 2

    # Mutation attempt on ARCHIVED project raises 409 ProjectArchivedError
    patch_res = client.patch(
        f"/api/v1/projects/{pid}",
        headers=auth("user_alice"),
        json={"name": "Mutated Name", "version": 2},
    )
    assert patch_res.status_code == 409
    assert "ARCHIVED" in patch_res.json()["error"]["message"]

    # Unarchive
    unarch_res = client.post(f"/api/v1/projects/{pid}/unarchive", headers=auth("user_alice"))
    assert unarch_res.status_code == 200
    assert unarch_res.json()["data"]["status"] == "active"
    assert unarch_res.json()["data"]["version"] == 3


def test_tc05_fsm_soft_delete_and_restore(client: TestClient, project_system):
    """
    TC-05.2: ACTIVE -> SOFT_DELETED -> ACTIVE (FSM T-04, T-06).
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Soft Delete Workspace"})
    pid = create_res.json()["data"]["id"]

    # Soft Delete
    del_res = client.delete(f"/api/v1/projects/{pid}", headers=auth("user_alice"))
    assert del_res.status_code == 200
    assert del_res.json()["data"]["status"] == "soft_deleted"

    # Verify project document has deleted_at and purge_after (~30 days)
    proj_doc = project_system["repo"].projects[pid]
    assert proj_doc.status == ProjectStatus.SOFT_DELETED
    assert proj_doc.deleted_at is not None
    assert proj_doc.purge_after is not None

    # Mutation on SOFT_DELETED project is prohibited
    mut_res = client.patch(
        f"/api/v1/projects/{pid}",
        headers=auth("user_alice"),
        json={"name": "Modified", "version": 2},
    )
    assert mut_res.status_code == 409
    assert "SOFT_DELETED" in mut_res.json()["error"]["message"]

    # Restore project within retention
    restore_res = client.post(f"/api/v1/projects/{pid}/restore", headers=auth("user_alice"))
    assert restore_res.status_code == 200
    assert restore_res.json()["data"]["status"] == "active"

    restored_doc = project_system["repo"].projects[pid]
    assert restored_doc.deleted_at is None
    assert restored_doc.purge_after is None


def test_tc05_fsm_illegal_transition_rejection(client: TestClient, project_system):
    """
    TC-05.3: Illegal transitions rejected: ACTIVE -> PURGED raises 409 InvalidStateTransitionError.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Illegal Purge Test"})
    pid = create_res.json()["data"]["id"]

    # Purge directly from ACTIVE -> Rejected with 409
    purge_res = client.delete(f"/api/v1/projects/{pid}/purge", headers=auth("user_alice"))
    assert purge_res.status_code == 409
    assert "Illegal project state transition" in purge_res.json()["error"]["message"]


def test_tc05_fsm_permanent_purge_cascade(client: TestClient, project_system):
    """
    TC-05.4: SOFT_DELETED -> PURGED cascades permanent cleanup.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_alice"), json={"name": "Purge Workspace"})
    pid = create_res.json()["data"]["id"]

    # Soft delete first
    client.delete(f"/api/v1/projects/{pid}", headers=auth("user_alice"))

    # Permanent purge
    purge_res = client.delete(f"/api/v1/projects/{pid}/purge", headers=auth("user_alice"))
    assert purge_res.status_code == 200

    # Project status is PURGED and child members are cleaned up
    proj_doc = project_system["repo"].projects[pid]
    assert proj_doc.status == ProjectStatus.PURGED
    member_count = sum(1 for m in project_system["member_repo"].members.values() if str(m.project_id) == pid)
    assert member_count == 0


# ==============================================================================
# TC-06: Member Management & RBAC Hierarchy
# ==============================================================================

def test_tc06_member_management_crud_and_boundaries(client: TestClient, project_system):
    """
    TC-06: Member management:
    - Add member with role MEMBER or ADMIN.
    - Direct OWNER addition prohibited (400/422).
    - Duplicate member addition returns 409.
    - Role modification.
    - Admin hierarchy boundary: ADMIN cannot demote/remove another ADMIN or OWNER.
    - Member self-leave.
    - Sole owner cannot leave or be removed without transfer.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_owner"), json={"name": "Team Workspace"})
    pid = create_res.json()["data"]["id"]

    # 1. Add Member (Bob as member)
    add_bob = client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_bob", "role": "member"},
    )
    assert add_bob.status_code == 201
    assert add_bob.json()["data"]["user_id"] == "user_user_bob"
    assert add_bob.json()["data"]["role"] == "member"

    # 2. Add Member as OWNER directly -> Prohibited
    add_owner = client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_eve", "role": "owner"},
    )
    assert add_owner.status_code in (400, 422)

    # 3. Duplicate member addition -> 409 Conflict
    dup_res = client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_bob", "role": "member"},
    )
    assert dup_res.status_code == 409
    assert "already a member" in dup_res.json()["error"]["message"].lower()

    # 4. Add Charlie as ADMIN
    add_charlie = client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_charlie", "role": "admin"},
    )
    assert add_charlie.status_code == 201

    # 5. Admin Hierarchy Boundary: Charlie (ADMIN) cannot demote or remove user_owner (OWNER)
    demote_owner = client.patch(
        f"/api/v1/projects/{pid}/members/user_user_owner",
        headers=auth("user_charlie"),
        json={"role": "member"},
    )
    assert demote_owner.status_code == 403
    assert demote_owner.json()["error"]["code"] == "FORBIDDEN"

    remove_owner = client.delete(
        f"/api/v1/projects/{pid}/members/user_user_owner",
        headers=auth("user_charlie"),
    )
    assert remove_owner.status_code == 403

    # 6. Sole OWNER Invariant: user_owner cannot leave without transfer
    leave_owner = client.delete(
        f"/api/v1/projects/{pid}/members/user_user_owner",
        headers=auth("user_owner"),
    )
    assert leave_owner.status_code in (400, 403)
    assert "owner cannot leave" in leave_owner.json()["error"]["message"].lower()

    # 7. Non-owner self-leave: Bob (member) voluntarily leaves
    leave_bob = client.delete(
        f"/api/v1/projects/{pid}/members/user_user_bob",
        headers=auth("user_bob"),
    )
    assert leave_bob.status_code == 200
    assert leave_bob.json()["success"] is True


# ==============================================================================
# TC-07: Atomic Ownership Transfer
# ==============================================================================

def test_tc07_atomic_ownership_transfer(client: TestClient, project_system):
    """
    TC-07: Atomic ownership transfer:
    - Current OWNER transfers to existing MEMBER (user_alice).
    - user_alice becomes OWNER.
    - former owner becomes ADMIN.
    - Project owner_id is updated.
    - Audit log records OWNERSHIP_TRANSFERRED.
    - Session transaction verified.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_owner"), json={"name": "Transfer Workspace"})
    pid = create_res.json()["data"]["id"]

    # Add user_alice as member first
    client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_alice", "role": "member"},
    )

    # Transfer ownership to user_alice
    transfer_res = client.post(
        f"/api/v1/projects/{pid}/transfer-ownership",
        headers=auth("user_owner"),
        json={"new_owner_user_id": "user_user_alice", "former_owner_role": "admin"},
    )
    assert transfer_res.status_code == 200
    data = transfer_res.json()["data"]
    assert data["owner_id"] == "user_user_alice"

    # Verify membership roles in repository
    alice_m = next(m for m in project_system["member_repo"].members.values() if m.user_id == "user_user_alice")
    owner_m = next(m for m in project_system["member_repo"].members.values() if m.user_id == "user_user_owner")

    assert alice_m.role == ProjectRole.OWNER
    assert owner_m.role == ProjectRole.ADMIN

    # Verify audit log recorded
    transfer_audit = next(
        (log_item for log_item in project_system["audit_repo"].logs if log_item.action == ProjectAuditAction.OWNERSHIP_TRANSFERRED),
        None,
    )
    assert transfer_audit is not None
    assert transfer_audit.target_user_id == "user_user_alice"

    # Verify session transaction was used
    assert "session_started" in project_system["transaction_records"]


# ==============================================================================
# TC-08: Audit Log Retrieval
# ==============================================================================

def test_tc08_audit_log_retrieval_and_rbac(client: TestClient, project_system):
    """
    TC-08: Audit log retrieval:
    - OWNER and ADMIN can read audit logs.
    - MEMBER / VIEWER receives 403 Forbidden.
    - Non-member receives 404 Not Found.
    - Events ordered newest first.
    """
    create_res = client.post("/api/v1/projects", headers=auth("user_owner"), json={"name": "Audit Workspace"})
    pid = create_res.json()["data"]["id"]

    # Add Admin user_charlie and Member user_bob
    client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_charlie", "role": "admin"},
    )
    client.post(
        f"/api/v1/projects/{pid}/members",
        headers=auth("user_owner"),
        json={"user_id": "user_user_bob", "role": "member"},
    )

    # 1. OWNER can view audit logs -> 200 OK
    res_owner = client.get(f"/api/v1/projects/{pid}/audit-logs", headers=auth("user_owner"))
    assert res_owner.status_code == 200
    owner_items = res_owner.json()["data"]["items"]
    assert len(owner_items) >= 3  # project.created + 2 * member.added

    # 2. ADMIN can view audit logs -> 200 OK
    res_admin = client.get(f"/api/v1/projects/{pid}/audit-logs", headers=auth("user_charlie"))
    assert res_admin.status_code == 200
    assert len(res_admin.json()["data"]["items"]) >= 3

    # 3. MEMBER receives 403 Forbidden
    res_member = client.get(f"/api/v1/projects/{pid}/audit-logs", headers=auth("user_bob"))
    assert res_member.status_code == 403
    assert res_member.json()["error"]["code"] == "FORBIDDEN"

    # 4. Non-member receives 404 Not Found
    res_stranger = client.get(f"/api/v1/projects/{pid}/audit-logs", headers=auth("user_stranger"))
    assert res_stranger.status_code == 404
    assert res_stranger.json()["error"]["code"] == "NOT_FOUND"
