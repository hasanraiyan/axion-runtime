from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from beanie import init_beanie
from bson import ObjectId
import pytest
from fastapi.testclient import TestClient

from app.api.deps import (
    get_current_user,
    get_project_audit_service,
    get_project_member_repository,
    get_project_member_service,
    get_project_repository,
    get_project_service,
)
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.main import app
from app.models import DOCUMENT_MODELS
from app.models.project import Project, ProjectMember, ProjectRole, ProjectSettings, ProjectStatus
from app.models.user import UserRole
from app.schemas.auth import AuthenticatedUser
from app.schemas.project import (
    AuditLogResponse,
    MemberResponse,
    ProjectResponse,
    ProjectSummaryResponse,
)


@pytest.fixture(autouse=True)
async def init_mock_beanie():
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
def mock_project_services():
    mock_p_service = MagicMock()
    mock_m_service = MagicMock()
    mock_a_service = MagicMock()
    mock_p_repo = MagicMock()
    mock_m_repo = MagicMock()

    regular_user = AuthenticatedUser(
        id="user_testuser",
        clerk_id="user_testuser",
        email="testuser@example.com",
        first_name="Test",
        last_name="User",
        role=UserRole.USER,
        roles=["user"],
        is_active=True,
        is_authenticated=True,
    )

    app.dependency_overrides[get_current_user] = lambda: regular_user
    app.dependency_overrides[get_project_service] = lambda: mock_p_service
    app.dependency_overrides[get_project_member_service] = lambda: mock_m_service
    app.dependency_overrides[get_project_audit_service] = lambda: mock_a_service
    app.dependency_overrides[get_project_repository] = lambda: mock_p_repo
    app.dependency_overrides[get_project_member_repository] = lambda: mock_m_repo

    yield {
        "project_service": mock_p_service,
        "member_service": mock_m_service,
        "audit_service": mock_a_service,
        "project_repo": mock_p_repo,
        "member_repo": mock_m_repo,
        "current_user": regular_user,
    }

    app.dependency_overrides.clear()


def sample_project_doc(pid="507f1f77bcf86cd799439011", name="Acme Platform", slug="acme-platform", owner_id="user_testuser", status=ProjectStatus.ACTIVE, version=1):
    obj_id = ObjectId(pid)
    proj = Project(
        name=name,
        slug=slug,
        owner_id=owner_id,
        status=status,
        version=version,
    )
    proj.id = obj_id
    return proj


def sample_project_response(pid="507f1f77bcf86cd799439011", name="Acme Platform", slug="acme-platform", role=ProjectRole.OWNER, status=ProjectStatus.ACTIVE, version=1):
    return ProjectResponse(
        id=pid,
        name=name,
        slug=slug,
        owner_id="user_testuser",
        status=status,
        tags=["prod"],
        settings=ProjectSettings(),
        metadata={},
        version=version,
        user_role=role,
        member_count=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


# ------------------------------------------------------------------------------
# 1. Project Creation & Listing Tests
# ------------------------------------------------------------------------------


def test_create_project_endpoint_happy_path(client: TestClient, auth_headers: dict, mock_project_services):
    expected_resp = sample_project_response()
    mock_project_services["project_service"].create_project = AsyncMock(return_value=expected_resp)

    response = client.post(
        "/api/v1/projects",
        headers=auth_headers,
        json={"name": "Acme Platform"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["data"]["name"] == "Acme Platform"
    assert data["data"]["slug"] == "acme-platform"
    assert data["data"]["user_role"] == "owner"


def test_create_project_slug_conflict(client: TestClient, auth_headers: dict, mock_project_services):
    mock_project_services["project_service"].create_project = AsyncMock(
        side_effect=ConflictError("Project slug already in use")
    )

    response = client.post(
        "/api/v1/projects",
        headers=auth_headers,
        json={"name": "Acme Platform", "slug": "acme-platform"},
    )
    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "CONFLICT"


def test_list_projects_endpoint(client: TestClient, auth_headers: dict, mock_project_services):
    summary = ProjectSummaryResponse(
        id="507f1f77bcf86cd799439011",
        name="Acme Platform",
        slug="acme-platform",
        owner_id="user_testuser",
        status=ProjectStatus.ACTIVE,
        tags=["prod"],
        user_role=ProjectRole.OWNER,
        member_count=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    mock_project_services["project_service"].list_projects = AsyncMock(return_value=([summary], 1))

    response = client.get("/api/v1/projects?search=acme&page=1&page_size=10", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]["items"]) == 1
    assert data["data"]["pagination"]["total_records"] == 1


# ------------------------------------------------------------------------------
# 2. RBAC & Multi-Tenant Isolation Dependency Tests
# ------------------------------------------------------------------------------


def test_get_project_non_member_yields_404_tenant_isolation(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    # Caller is not a member:
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=None)

    response = client.get(f"/api/v1/projects/{proj.id}", headers=auth_headers)
    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "NOT_FOUND"


def test_get_project_happy_path(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.VIEWER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    expected_resp = sample_project_response(role=ProjectRole.VIEWER)
    mock_project_services["project_service"].get_project = AsyncMock(return_value=expected_resp)

    response = client.get(f"/api/v1/projects/{proj.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["id"] == str(proj.id)


def test_update_project_insufficient_role_forbidden(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    # User is only a VIEWER, requires ADMIN or OWNER
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.VIEWER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    response = client.patch(
        f"/api/v1/projects/{proj.id}",
        headers=auth_headers,
        json={"name": "New Name", "version": 1},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "FORBIDDEN"


def test_update_project_occ_conflict(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc(version=2)
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.ADMIN)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    mock_project_services["project_service"].update_project = AsyncMock(
        side_effect=ConflictError("Project version conflict: document was modified by a concurrent request")
    )

    response = client.patch(
        f"/api/v1/projects/{proj.id}",
        headers=auth_headers,
        json={"name": "New Name", "version": 1},
    )
    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "CONFLICT"


# ------------------------------------------------------------------------------
# 3. FSM Lifecycle Endpoints Tests
# ------------------------------------------------------------------------------


def test_archive_and_unarchive_endpoints(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    archived_resp = sample_project_response(status=ProjectStatus.ARCHIVED, version=2)
    mock_project_services["project_service"].archive_project = AsyncMock(return_value=archived_resp)

    # Archive
    response = client.post(f"/api/v1/projects/{proj.id}/archive", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "archived"

    # Unarchive
    active_resp = sample_project_response(status=ProjectStatus.ACTIVE, version=3)
    mock_project_services["project_service"].unarchive_project = AsyncMock(return_value=active_resp)

    response_unarchive = client.post(f"/api/v1/projects/{proj.id}/unarchive", headers=auth_headers)
    assert response_unarchive.status_code == 200
    assert response_unarchive.json()["data"]["status"] == "active"


def test_soft_delete_and_restore_endpoints(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    deleted_resp = sample_project_response(status=ProjectStatus.SOFT_DELETED, version=2)
    mock_project_services["project_service"].soft_delete_project = AsyncMock(return_value=deleted_resp)

    # Soft delete
    response_del = client.delete(f"/api/v1/projects/{proj.id}", headers=auth_headers)
    assert response_del.status_code == 200
    assert response_del.json()["data"]["status"] == "soft_deleted"

    # Restore
    restored_resp = sample_project_response(status=ProjectStatus.ACTIVE, version=3)
    mock_project_services["project_service"].restore_project = AsyncMock(return_value=restored_resp)

    # Mock proj in soft_deleted state
    deleted_proj = sample_project_doc(status=ProjectStatus.SOFT_DELETED, version=2)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=deleted_proj)

    response_restore = client.post(f"/api/v1/projects/{proj.id}/restore", headers=auth_headers)
    assert response_restore.status_code == 200
    assert response_restore.json()["data"]["status"] == "active"


def test_purge_endpoint_illegal_transition(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc(status=ProjectStatus.ACTIVE)
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    mock_project_services["project_service"].purge_project = AsyncMock(
        side_effect=InvalidStateTransitionError(from_state="active", to_state="purged")
    )

    response = client.delete(f"/api/v1/projects/{proj.id}/purge", headers=auth_headers)
    assert response.status_code == 409
    assert "Illegal project state transition from 'active' to 'purged'" in response.json()["error"]["message"]


def test_transfer_ownership_endpoint(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    transferred_resp = sample_project_response(role=ProjectRole.ADMIN, version=2)
    mock_project_services["project_service"].transfer_ownership = AsyncMock(return_value=transferred_resp)

    response = client.post(
        f"/api/v1/projects/{proj.id}/transfer-ownership",
        headers=auth_headers,
        json={"new_owner_user_id": "user_new_owner", "former_owner_role": "admin"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True


# ------------------------------------------------------------------------------
# 4. Member Management Endpoints Tests
# ------------------------------------------------------------------------------


def test_member_crud_endpoints(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member_owner = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member_owner)

    member_resp = MemberResponse(
        id="507f1f77bcf86cd799439099",
        project_id=str(proj.id),
        user_id="user_bob",
        role=ProjectRole.MEMBER,
        invited_by="user_testuser",
        joined_at=datetime.now(timezone.utc),
    )

    # 1. Add Member
    mock_project_services["member_service"].add_member = AsyncMock(return_value=member_resp)
    res_add = client.post(
        f"/api/v1/projects/{proj.id}/members",
        headers=auth_headers,
        json={"user_id": "user_bob", "role": "member"},
    )
    assert res_add.status_code == 201
    assert res_add.json()["data"]["user_id"] == "user_bob"

    # 2. List Members
    mock_project_services["member_service"].list_members = AsyncMock(return_value=([member_resp], 1))
    res_list = client.get(f"/api/v1/projects/{proj.id}/members", headers=auth_headers)
    assert res_list.status_code == 200
    assert len(res_list.json()["data"]["items"]) == 1

    # 3. Update Member Role
    updated_member = MemberResponse(
        id="507f1f77bcf86cd799439099",
        project_id=str(proj.id),
        user_id="user_bob",
        role=ProjectRole.ADMIN,
        invited_by="user_testuser",
        joined_at=datetime.now(timezone.utc),
    )
    mock_project_services["member_service"].update_member_role = AsyncMock(return_value=updated_member)
    res_role = client.patch(
        f"/api/v1/projects/{proj.id}/members/user_bob",
        headers=auth_headers,
        json={"role": "admin"},
    )
    assert res_role.status_code == 200
    assert res_role.json()["data"]["role"] == "admin"

    # 4. Remove Member
    mock_project_services["member_service"].remove_member = AsyncMock(
        return_value={"message": "Member 'user_bob' successfully removed", "removed": True}
    )
    res_remove = client.delete(f"/api/v1/projects/{proj.id}/members/user_bob", headers=auth_headers)
    assert res_remove.status_code == 200
    assert res_remove.json()["success"] is True


def test_remove_member_sole_owner_forbidden(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member_owner = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.OWNER)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member_owner)

    mock_project_services["member_service"].remove_member = AsyncMock(
        side_effect=ForbiddenError("The project OWNER cannot leave or be removed without transferring ownership first")
    )
    response = client.delete(f"/api/v1/projects/{proj.id}/members/user_testuser", headers=auth_headers)
    assert response.status_code == 403
    assert "The project OWNER cannot leave or be removed" in response.json()["error"]["message"]


# ------------------------------------------------------------------------------
# 5. Audit Log Retrieval Endpoints Tests
# ------------------------------------------------------------------------------


def test_list_audit_logs_endpoint(client: TestClient, auth_headers: dict, mock_project_services):
    proj = sample_project_doc()
    member = ProjectMember(project_id=proj.id, user_id="user_testuser", role=ProjectRole.ADMIN)
    mock_project_services["project_repo"].get_by_id_or_slug = AsyncMock(return_value=proj)
    mock_project_services["member_repo"].get_membership = AsyncMock(return_value=member)

    log_item = AuditLogResponse(
        id="507f1f77bcf86cd799439088",
        project_id=str(proj.id),
        actor_id="user_testuser",
        action="project.created",
        payload={"name": "Acme Platform"},
        created_at=datetime.now(timezone.utc),
    )
    mock_project_services["audit_service"].list_audit_logs = AsyncMock(return_value=([log_item], 1))

    response = client.get(f"/api/v1/projects/{proj.id}/audit-logs", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]["items"]) == 1
    assert data["data"]["items"][0]["action"] == "project.created"
