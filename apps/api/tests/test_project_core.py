from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
import pytest
from pydantic import ValidationError

from app.core.exceptions import (
    ProjectFSMError,
    InvalidStateTransitionError,
    ProjectNotActiveError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
    ConflictError,
    NotFoundError,
)
from app.models.project import (
    Project,
    ProjectMember,
    ProjectAuditLog,
    ProjectStatus,
    ProjectRole,
    ProjectAuditAction,
    ProjectSettings,
)
from app.models import DOCUMENT_MODELS
from app.schemas.project import (
    ProjectCreateRequest,
    ProjectUpdateRequest,
    ProjectResponse,
    ProjectSummaryResponse,
    AddMemberRequest,
    UpdateMemberRoleRequest,
    MemberResponse,
    TransferOwnershipRequest,
    AuditLogResponse,
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


def test_fsm_exceptions():
    fsm_err = ProjectFSMError("State machine error")
    assert isinstance(fsm_err, ConflictError)
    assert fsm_err.status_code == 409

    trans_err = InvalidStateTransitionError("active", "purged")
    assert isinstance(trans_err, ProjectFSMError)
    assert "Illegal project state transition from 'active' to 'purged'" in str(trans_err.detail)

    not_active = ProjectNotActiveError("Not active")
    assert isinstance(not_active, ProjectFSMError)

    archived_err = ProjectArchivedError("proj_123")
    assert isinstance(archived_err, ProjectNotActiveError)
    assert "proj_123" in str(archived_err.detail)
    assert "ARCHIVED" in str(archived_err.detail)

    deleted_err = ProjectDeletedError("proj_123")
    assert isinstance(deleted_err, ProjectNotActiveError)
    assert "proj_123" in str(deleted_err.detail)
    assert "SOFT_DELETED" in str(deleted_err.detail)

    purged_err = ProjectPurgedError("proj_123")
    assert isinstance(purged_err, NotFoundError)
    assert purged_err.status_code == 404
    assert "proj_123" in str(purged_err.detail)


def test_document_models_registration():
    assert Project in DOCUMENT_MODELS
    assert ProjectMember in DOCUMENT_MODELS
    assert ProjectAuditLog in DOCUMENT_MODELS


def test_models_instantiation():
    settings = ProjectSettings(default_environment="staging", retention_days=60)
    assert settings.retention_days == 60

    proj = Project(
        name="Platform Core",
        slug="platform-core",
        owner_id="user_clerk_123",
        settings=settings,
    )
    assert proj.status == ProjectStatus.ACTIVE
    assert proj.version == 1
    assert proj.Settings.name == "projects"
    assert len(proj.Settings.indexes) >= 6

    member = ProjectMember(
        project_id=PydanticObjectId(),
        user_id="user_clerk_456",
        role=ProjectRole.ADMIN,
    )
    assert member.role == ProjectRole.ADMIN
    assert member.Settings.name == "project_members"

    audit = ProjectAuditLog(
        project_id=PydanticObjectId(),
        actor_id="user_clerk_123",
        action=ProjectAuditAction.PROJECT_CREATED,
        payload={"name": "Platform Core"},
    )
    assert audit.action == ProjectAuditAction.PROJECT_CREATED
    assert audit.Settings.name == "project_audit_logs"


def test_schemas_project_create():
    req = ProjectCreateRequest(name="New Project", slug="valid-slug-123")
    assert req.slug == "valid-slug-123"

    update_req = ProjectUpdateRequest(name="Updated Name", version=1)
    assert update_req.name == "Updated Name"
    assert update_req.version == 1

    with pytest.raises(ValidationError):
        ProjectCreateRequest(name="P", slug="valid-slug")  # min_length 2

    with pytest.raises(ValidationError):
        ProjectCreateRequest(name="Valid Name", slug="Invalid Slug")  # invalid regex


def test_schemas_member_role_validators():
    # Direct OWNER role assignment should fail
    with pytest.raises(ValidationError):
        AddMemberRequest(user_id="user_1", role=ProjectRole.OWNER)

    valid_add = AddMemberRequest(user_id="user_1", role=ProjectRole.MEMBER)
    assert valid_add.role == ProjectRole.MEMBER

    with pytest.raises(ValidationError):
        UpdateMemberRoleRequest(role=ProjectRole.OWNER)

    valid_update = UpdateMemberRoleRequest(role=ProjectRole.ADMIN)
    assert valid_update.role == ProjectRole.ADMIN

    with pytest.raises(ValidationError):
        TransferOwnershipRequest(new_owner_user_id="user_2", former_owner_role=ProjectRole.OWNER)

    valid_transfer = TransferOwnershipRequest(new_owner_user_id="user_2", former_owner_role=ProjectRole.MEMBER)
    assert valid_transfer.former_owner_role == ProjectRole.MEMBER


def test_schemas_response_serialization():
    now = datetime.now(timezone.utc)
    proj_id = PydanticObjectId()

    resp = ProjectResponse(
        id=proj_id,
        name="Platform Core",
        slug="platform-core",
        owner_id="user_1",
        status=ProjectStatus.ACTIVE,
        settings=ProjectSettings(),
        version=1,
        created_at=now,
        updated_at=now,
    )
    assert isinstance(resp.id, str)
    assert resp.id == str(proj_id)

    summary = ProjectSummaryResponse(
        id=proj_id,
        name="Platform Core",
        slug="platform-core",
        owner_id="user_1",
        status=ProjectStatus.ACTIVE,
        tags=["prod"],
        user_role=ProjectRole.OWNER,
        member_count=1,
        created_at=now,
        updated_at=now,
    )
    assert isinstance(summary.id, str)

    member_id = PydanticObjectId()
    member_resp = MemberResponse(
        id=member_id,
        project_id=proj_id,
        user_id="user_1",
        role=ProjectRole.OWNER,
        joined_at=now,
    )
    assert member_resp.id == str(member_id)
    assert member_resp.project_id == str(proj_id)

    audit_id = PydanticObjectId()
    audit_resp = AuditLogResponse(
        id=audit_id,
        project_id=proj_id,
        actor_id="user_1",
        action=ProjectAuditAction.PROJECT_CREATED.value,
        created_at=now,
    )
    assert audit_resp.id == str(audit_id)
    assert audit_resp.project_id == str(proj_id)
