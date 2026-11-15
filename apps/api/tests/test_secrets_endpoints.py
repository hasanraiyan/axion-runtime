from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from beanie import init_beanie
from bson import ObjectId
import pytest

from app.api.deps import (
    get_current_user,
    get_project_member_repository,
    get_project_repository,
    get_runtime_secret_resolver,
    get_secret_service,
)
from app.core.exceptions import (
    ConflictError,
    CryptographicIntegrityError,
    ProjectArchivedError,
)
from app.main import app
from app.middleware.logging import (
    REDACTED_BODY,
    is_redacted_path,
    redact_body,
    redact_payload,
)
from app.models import DOCUMENT_MODELS
from app.models.project import Project, ProjectMember, ProjectRole, ProjectStatus
from app.models.user import UserRole
from app.schemas.auth import AuthenticatedUser
from app.schemas.secret import (
    SecretBatchResolveResponse,
    SecretResponse,
    SecretSummaryResponse,
    SecretValueResponse,
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


def make_user(user_id="user_test", role=UserRole.USER):
    return AuthenticatedUser(
        id=user_id,
        clerk_id=user_id,
        email=f"{user_id}@example.com",
        first_name="Test",
        last_name="User",
        role=role,
        roles=[role.value],
        is_active=True,
        is_authenticated=True,
    )


@pytest.fixture
def test_setup():
    project_id = "507f1f77bcf86cd799439011"
    proj_oid = ObjectId(project_id)

    mock_p_repo = MagicMock()
    mock_m_repo = MagicMock()
    mock_s_service = MagicMock()
    mock_r_resolver = MagicMock()

    # Active project
    active_proj = Project(
        name="Active Project",
        slug="active-project",
        owner_id="user_owner",
        status=ProjectStatus.ACTIVE,
        version=1,
    )
    active_proj.id = proj_oid

    mock_p_repo.get_by_id_or_slug = AsyncMock(return_value=active_proj)
    mock_m_repo.get_membership = AsyncMock()

    app.dependency_overrides[get_project_repository] = lambda: mock_p_repo
    app.dependency_overrides[get_project_member_repository] = lambda: mock_m_repo
    app.dependency_overrides[get_secret_service] = lambda: mock_s_service
    app.dependency_overrides[get_runtime_secret_resolver] = lambda: mock_r_resolver

    yield {
        "project_id": project_id,
        "project": active_proj,
        "project_repo": mock_p_repo,
        "member_repo": mock_m_repo,
        "secret_service": mock_s_service,
        "runtime_resolver": mock_r_resolver,
    }

    app.dependency_overrides.clear()


def sample_secret_response(
    sid="507f1f77bcf86cd799439099",
    pid="507f1f77bcf86cd799439011",
    name="OPENAI_API_KEY",
    env="production",
    revision=1,
    last_rotated_at=None,
):
    now = datetime.now(timezone.utc)
    return SecretResponse(
        id=sid,
        project_id=pid,
        name=name,
        environment=env,
        description="OpenAI API Key",
        tags=["ai", "prod"],
        is_system=False,
        revision=revision,
        last_rotated_at=last_rotated_at,
        expires_at=None,
        created_at=now,
        updated_at=now,
        algorithm="AES-256-GCM",
        kek_id="local-v1",
        created_by="user_admin",
        updated_by="user_admin",
    )


# ------------------------------------------------------------------------------
# 1. Happy Path Secret Lifecycle Tests
# ------------------------------------------------------------------------------


def test_secret_lifecycle_create(test_setup, client, auth_headers):
    """POST /projects/{project_id}/secrets: Create secret returns 201 with metadata only."""
    pid = test_setup["project_id"]
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    expected_resp = sample_secret_response(name="NEW_SECRET", revision=1)
    test_setup["secret_service"].create_secret = AsyncMock(return_value=expected_resp)

    payload = {
        "name": "NEW_SECRET",
        "value": "super_secret_value_12345",
        "environment": "production",
        "description": "Production API key",
        "tags": ["env:prod"],
    }

    res = client.post(f"/api/v1/projects/{pid}/secrets", json=payload, headers=auth_headers)
    assert res.status_code == 201
    body = res.json()
    assert body["data"]["name"] == "NEW_SECRET"
    assert body["data"]["revision"] == 1
    assert "value" not in body["data"]
    assert "ciphertext" not in body["data"]


def test_secret_lifecycle_list(test_setup, client, auth_headers):
    """GET /projects/{project_id}/secrets: List secret metadata returns paginated summaries with zero plaintext."""
    pid = test_setup["project_id"]
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_viewer", role=ProjectRole.VIEWER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_viewer")

    summary = SecretSummaryResponse(
        id="507f1f77bcf86cd799439099",
        project_id=pid,
        name="OPENAI_API_KEY",
        environment="production",
        description="OpenAI API Key",
        tags=["ai"],
        is_system=False,
        revision=1,
        last_rotated_at=None,
        expires_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    test_setup["secret_service"].list_secrets = AsyncMock(return_value=([summary], 1))

    res = client.get(f"/api/v1/projects/{pid}/secrets", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["data"]["items"][0]["name"] == "OPENAI_API_KEY"
    assert body["data"]["pagination"]["total_records"] == 1
    assert "value" not in body["data"]["items"][0]


def test_secret_lifecycle_get(test_setup, client, auth_headers):
    """GET /projects/{project_id}/secrets/{secret_id}: Inspect single secret metadata."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_viewer", role=ProjectRole.VIEWER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_viewer")

    resp = sample_secret_response(sid=sid, pid=pid, name="DATABASE_URL")
    test_setup["secret_service"].get_secret_metadata = AsyncMock(return_value=resp)

    res = client.get(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["data"]["name"] == "DATABASE_URL"
    assert body["data"]["algorithm"] == "AES-256-GCM"
    assert "value" not in body["data"]


def test_secret_lifecycle_update_occ(test_setup, client, auth_headers):
    """PUT /projects/{project_id}/secrets/{secret_id}: In-place update with OCC check."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    updated_resp = sample_secret_response(sid=sid, pid=pid, revision=2)
    test_setup["secret_service"].update_secret = AsyncMock(return_value=updated_resp)

    payload = {
        "description": "Updated description",
        "revision": 1,
    }
    res = client.put(f"/api/v1/projects/{pid}/secrets/{sid}", json=payload, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["data"]["revision"] == 2


def test_secret_lifecycle_rotate(test_setup, client, auth_headers):
    """POST /projects/{project_id}/secrets/{secret_id}/rotate: In-place rotation."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    rotated_resp = sample_secret_response(
        sid=sid, pid=pid, revision=3, last_rotated_at=datetime.now(timezone.utc)
    )
    test_setup["secret_service"].rotate_secret = AsyncMock(return_value=rotated_resp)

    payload = {
        "new_value": "brand_new_rotated_secret_val",
        "revision": 2,
    }
    res = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/rotate", json=payload, headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["data"]["revision"] == 3
    assert body["data"]["last_rotated_at"] is not None


def test_secret_lifecycle_reveal(test_setup, client, auth_headers):
    """POST /projects/{project_id}/secrets/{secret_id}/reveal: Privileged reveal returns plaintext + anti-cache headers."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    reveal_resp = SecretValueResponse(
        id=sid,
        name="OPENAI_API_KEY",
        environment="production",
        value="sk-actual-decrypted-plaintext",
        revealed_at=datetime.now(timezone.utc),
        audit_logged=True,
    )
    test_setup["secret_service"].reveal_secret_value = AsyncMock(return_value=reveal_resp)

    payload = {"reason": "Auditing for production deployment"}
    res = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", json=payload, headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["data"]["value"] == "sk-actual-decrypted-plaintext"
    assert body["data"]["audit_logged"] is True

    # Verify anti-caching headers per SRS Section 7.1
    assert "no-store" in res.headers["Cache-Control"]
    assert "no-cache" in res.headers["Cache-Control"]
    assert "must-revalidate" in res.headers["Cache-Control"]
    assert "private" in res.headers["Cache-Control"]
    assert res.headers.get("Pragma") == "no-cache"


def test_secret_lifecycle_soft_delete(test_setup, client, auth_headers):
    """DELETE /projects/{project_id}/secrets/{secret_id}: Soft-delete secret."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    test_setup["secret_service"].delete_secret = AsyncMock(return_value=True)

    res = client.delete(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["message"] == "Secret deleted successfully"


# ------------------------------------------------------------------------------
# 2. In-Place Replacement & Concurrency Control (OCC)
# ------------------------------------------------------------------------------


def test_occ_race_condition_conflict(test_setup, client, auth_headers):
    """Update or rotate with stale revision returns 409 Conflict."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    # Simulate OCC conflict in service
    test_setup["secret_service"].update_secret = AsyncMock(
        side_effect=ConflictError("Secret has been modified by another process. Please reload and retry.")
    )

    payload = {
        "description": "Conflict update",
        "revision": 1,
    }
    res = client.put(f"/api/v1/projects/{pid}/secrets/{sid}", json=payload, headers=auth_headers)
    assert res.status_code == 409
    assert "Secret has been modified" in res.json()["error"]["message"]


# ------------------------------------------------------------------------------
# 3. Cryptographic Tampering & Integrity Verification
# ------------------------------------------------------------------------------


def test_aad_translocation_tampering_integrity_error(test_setup, client, auth_headers):
    """Tampering project_id, environment, or name causes CryptographicIntegrityError (500)."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    test_setup["secret_service"].reveal_secret_value = AsyncMock(
        side_effect=CryptographicIntegrityError("Ciphertext integrity verification failed")
    )

    res = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", headers=auth_headers)
    assert res.status_code == 500
    assert "integrity verification failed" in res.json()["error"]["message"]


# ------------------------------------------------------------------------------
# 4. Privilege Escalation & RBAC Boundary Tests
# ------------------------------------------------------------------------------


def test_privilege_escalation_reveal_forbidden_for_member_and_viewer(test_setup, client, auth_headers):
    """MEMBER and VIEWER are strictly forbidden (403) from /reveal."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"

    # MEMBER role
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_member", role=ProjectRole.MEMBER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_member")

    res = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", headers=auth_headers)
    assert res.status_code == 403
    assert "Insufficient project permissions" in res.json()["error"]["message"]

    # VIEWER role
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_viewer", role=ProjectRole.VIEWER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_viewer")

    res2 = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", headers=auth_headers)
    assert res2.status_code == 403
    assert "Insufficient project permissions" in res2.json()["error"]["message"]


def test_privilege_escalation_mutations_forbidden_for_member(test_setup, client, auth_headers):
    """MEMBER is forbidden (403) from mutations (create, update, rotate, delete)."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_member", role=ProjectRole.MEMBER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_member")

    # Create
    res_create = client.post(
        f"/api/v1/projects/{pid}/secrets",
        json={"name": "NEW_KEY", "value": "val"},
        headers=auth_headers,
    )
    assert res_create.status_code == 403

    # Update
    res_update = client.put(
        f"/api/v1/projects/{pid}/secrets/{sid}",
        json={"description": "new desc", "revision": 1},
        headers=auth_headers,
    )
    assert res_update.status_code == 403

    # Rotate
    res_rotate = client.post(
        f"/api/v1/projects/{pid}/secrets/{sid}/rotate",
        json={"new_value": "rotated_val", "revision": 1},
        headers=auth_headers,
    )
    assert res_rotate.status_code == 403

    # Delete
    res_delete = client.delete(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers)
    assert res_delete.status_code == 403


# ------------------------------------------------------------------------------
# 5. Tenant Anti-Enumeration Tests
# ------------------------------------------------------------------------------


def test_tenant_anti_enumeration_non_member_receives_404(test_setup, client, auth_headers):
    """Non-members receive HTTP 404 on all endpoints to prevent resource enumeration."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"

    # User is NOT a member of the project
    test_setup["member_repo"].get_membership.return_value = None
    app.dependency_overrides[get_current_user] = lambda: make_user("outsider_user")

    # List
    assert client.get(f"/api/v1/projects/{pid}/secrets", headers=auth_headers).status_code == 404
    # Create
    assert client.post(f"/api/v1/projects/{pid}/secrets", json={"name": "K", "value": "v"}, headers=auth_headers).status_code == 404
    # Get
    assert client.get(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers).status_code == 404
    # Update
    assert client.put(f"/api/v1/projects/{pid}/secrets/{sid}", json={"revision": 1}, headers=auth_headers).status_code == 404
    # Rotate
    assert client.post(f"/api/v1/projects/{pid}/secrets/{sid}/rotate", json={"new_value": "v", "revision": 1}, headers=auth_headers).status_code == 404
    # Reveal
    assert client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", headers=auth_headers).status_code == 404
    # Delete
    assert client.delete(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers).status_code == 404
    # Resolve
    assert client.post(f"/api/v1/projects/{pid}/secrets/resolve", json={"names": ["K"]}, headers=auth_headers).status_code == 404


# ------------------------------------------------------------------------------
# 6. Project ARCHIVED State Freeze Tests
# ------------------------------------------------------------------------------


def test_project_archived_freeze_mutations_reject_reveal_allowed(test_setup, client, auth_headers):
    """Archived projects reject mutations with 409 Conflict, but allow metadata inspection and reveal."""
    pid = test_setup["project_id"]
    sid = "507f1f77bcf86cd799439099"

    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    # Mutations raise ProjectArchivedError in service
    test_setup["secret_service"].create_secret = AsyncMock(side_effect=ProjectArchivedError(pid))
    test_setup["secret_service"].update_secret = AsyncMock(side_effect=ProjectArchivedError(pid))
    test_setup["secret_service"].rotate_secret = AsyncMock(side_effect=ProjectArchivedError(pid))
    test_setup["secret_service"].delete_secret = AsyncMock(side_effect=ProjectArchivedError(pid))

    # Create -> 409
    res_c = client.post(f"/api/v1/projects/{pid}/secrets", json={"name": "K", "value": "v"}, headers=auth_headers)
    assert res_c.status_code == 409

    # Update -> 409
    res_u = client.put(f"/api/v1/projects/{pid}/secrets/{sid}", json={"revision": 1}, headers=auth_headers)
    assert res_u.status_code == 409

    # Rotate -> 409
    res_r = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/rotate", json={"new_value": "v", "revision": 1}, headers=auth_headers)
    assert res_r.status_code == 409

    # Delete -> 409
    res_d = client.delete(f"/api/v1/projects/{pid}/secrets/{sid}", headers=auth_headers)
    assert res_d.status_code == 409

    # Reveal -> Permitted on archived (200)
    reveal_resp = SecretValueResponse(
        id=sid,
        name="OPENAI_API_KEY",
        environment="production",
        value="archived_decrypted_val",
        revealed_at=datetime.now(timezone.utc),
        audit_logged=True,
    )
    test_setup["secret_service"].reveal_secret_value = AsyncMock(return_value=reveal_resp)
    res_reveal = client.post(f"/api/v1/projects/{pid}/secrets/{sid}/reveal", headers=auth_headers)
    assert res_reveal.status_code == 200
    assert res_reveal.json()["data"]["value"] == "archived_decrypted_val"


# ------------------------------------------------------------------------------
# 7. Runtime Batch Resolution Endpoint Tests
# ------------------------------------------------------------------------------


def test_batch_resolve_endpoint(test_setup, client, auth_headers):
    """POST /projects/{project_id}/secrets/resolve: Resolves batch runtime secrets for MEMBER+."""
    pid = test_setup["project_id"]

    # MEMBER role is allowed to resolve runtime secrets
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_member", role=ProjectRole.MEMBER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_member")

    mock_resolve_resp = SecretBatchResolveResponse(
        resolved={"OPENAI_API_KEY": "sk-12345", "PINECONE_KEY": "pc-67890"},
        missing=["UNKNOWN_KEY"],
    )
    test_setup["runtime_resolver"].resolve_secrets = AsyncMock(return_value=mock_resolve_resp)

    payload = {
        "names": ["OPENAI_API_KEY", "PINECONE_KEY", "UNKNOWN_KEY"],
        "environment": "production",
        "execution_id": "exec_abc_123",
    }
    res = client.post(f"/api/v1/projects/{pid}/secrets/resolve", json=payload, headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["data"]["resolved"]["OPENAI_API_KEY"] == "sk-12345"
    assert body["data"]["missing"] == ["UNKNOWN_KEY"]

    # VIEWER role is rejected (403) from /resolve
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_viewer", role=ProjectRole.VIEWER
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_viewer")
    res_viewer = client.post(f"/api/v1/projects/{pid}/secrets/resolve", json=payload, headers=auth_headers)
    assert res_viewer.status_code == 403


# ------------------------------------------------------------------------------
# 8. Logging Body Redaction Middleware Tests
# ------------------------------------------------------------------------------


def test_logging_body_redaction():
    """Verify that sensitive paths (/secrets, /reveal, /resolve) are redacted in HTTP logging."""
    sensitive_paths = [
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets",
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets/",
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets/507f1f77bcf86cd799439099",
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets/507f1f77bcf86cd799439099/reveal",
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets/507f1f77bcf86cd799439099/rotate",
        "/api/v1/projects/507f1f77bcf86cd799439011/secrets/resolve",
    ]

    for path in sensitive_paths:
        assert is_redacted_path(path) is True
        assert redact_body(path, {"value": "secret"}) == REDACTED_BODY
        assert redact_payload(path, "raw_sensitive_secret") == REDACTED_BODY

    # Non-sensitive paths must not be redacted
    normal_paths = [
        "/api/v1/health",
        "/api/v1/auth/me",
        "/api/v1/projects",
        "/api/v1/projects/507f1f77bcf86cd799439011",
        "/api/v1/projects/507f1f77bcf86cd799439011/members",
    ]

    for path in normal_paths:
        assert is_redacted_path(path) is False
        normal_data = {"status": "ok"}
        assert redact_body(path, normal_data) == normal_data
        assert redact_payload(path, normal_data) == normal_data


# ------------------------------------------------------------------------------
# 9. Schema & Validation Constraints (Regex, Bounds, Types)
# ------------------------------------------------------------------------------


def test_secret_name_validation(test_setup, client, auth_headers):
    """Secret name must match ^[A-Z0-9_]{1,128}$."""
    pid = test_setup["project_id"]
    test_setup["member_repo"].get_membership.return_value = ProjectMember(
        project_id=ObjectId(pid), user_id="user_admin", role=ProjectRole.ADMIN
    )
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")

    # Lowercase name -> 422
    res_lower = client.post(
        f"/api/v1/projects/{pid}/secrets",
        json={"name": "lowercase_key", "value": "some_value"},
        headers=auth_headers,
    )
    assert res_lower.status_code == 422

    # Special characters -> 422
    res_special = client.post(
        f"/api/v1/projects/{pid}/secrets",
        json={"name": "INVALID-DASHES!", "value": "some_value"},
        headers=auth_headers,
    )
    assert res_special.status_code == 422

    # Empty value -> 422
    res_empty_val = client.post(
        f"/api/v1/projects/{pid}/secrets",
        json={"name": "VALID_NAME", "value": ""},
        headers=auth_headers,
    )
    assert res_empty_val.status_code == 422
