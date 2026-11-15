import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
from beanie import init_beanie
from bson import ObjectId

from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    InvalidStateTransitionError,
    NotFoundError,
    ProjectPurgedError,
)
from app.models.project import (
    Project,
    ProjectAuditLog,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
from app.models.user import User
from app.schemas.project import (
    AddMemberRequest,
    ProjectCreateRequest,
    ProjectUpdateRequest,
    TransferOwnershipRequest,
    UpdateMemberRoleRequest,
)
from app.services.project_audit_service import ProjectAuditService
from app.services.project_member_service import ProjectMemberService
from app.services.project_service import ProjectService


@pytest.fixture
async def init_mock_beanie():
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])

    col = MagicMock()
    col.name = "projects"
    col.create_index = AsyncMock()
    col.create_indexes = AsyncMock(return_value=[])
    col.index_information = AsyncMock(return_value={})
    col.find_one = AsyncMock(return_value=None)
    col.count_documents = AsyncMock(return_value=0)
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
    db.__getitem__.return_value = col

    await init_beanie(database=db, document_models=[Project, ProjectMember, ProjectAuditLog, User])
    return db


@pytest.fixture
def mock_repos():
    proj_repo = MagicMock()
    member_repo = MagicMock()
    audit_repo = MagicMock()
    user_repo = MagicMock()

    # Async mock methods
    proj_repo.get_by_id = AsyncMock()
    proj_repo.get_by_slug = AsyncMock()
    proj_repo.get_by_id_or_slug = AsyncMock()
    proj_repo.list_by_ids = AsyncMock()
    proj_repo.create = AsyncMock()
    proj_repo.update = AsyncMock()
    proj_repo.update_with_version = AsyncMock()
    proj_repo.transition_status = AsyncMock()

    member_repo.get_membership = AsyncMock()
    member_repo.list_project_ids_for_user = AsyncMock()
    member_repo.list_members = AsyncMock()
    member_repo.count_members = AsyncMock()
    member_repo.create = AsyncMock()
    member_repo.update = AsyncMock()
    member_repo.delete = AsyncMock()
    member_repo.delete_by_project_id = AsyncMock()

    audit_repo.log_event = AsyncMock()
    audit_repo.list_events = AsyncMock()
    audit_repo.delete_by_project_id = AsyncMock()

    user_repo.get_by_clerk_id = AsyncMock()

    return {
        "proj_repo": proj_repo,
        "member_repo": member_repo,
        "audit_repo": audit_repo,
        "user_repo": user_repo,
    }


def make_sample_project(
    pid=None,
    name="Test Project",
    slug="test-project",
    owner_id="user_owner",
    status=ProjectStatus.ACTIVE,
    version=1,
    purge_after=None,
):
    obj_id = ObjectId(pid) if pid else ObjectId()
    proj = Project(
        name=name,
        slug=slug,
        owner_id=owner_id,
        status=status,
        version=version,
        purge_after=purge_after,
    )
    proj.id = obj_id
    return proj


def make_sample_member(project_id, user_id, role=ProjectRole.MEMBER):
    obj_id = ObjectId()
    member = ProjectMember(
        project_id=project_id,
        user_id=user_id,
        role=role,
    )
    member.id = obj_id
    return member


# ==============================================================================
# ProjectService Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_create_project_auto_slug(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    mock_repos["proj_repo"].get_by_slug.return_value = None
    created_proj = make_sample_project(name="Platform Services", slug="platform-services")
    mock_repos["proj_repo"].create.return_value = created_proj
    mock_repos["member_repo"].create.return_value = MagicMock()
    mock_repos["audit_repo"].log_event.return_value = MagicMock()

    req = ProjectCreateRequest(name="Platform Services")
    res = await service.create_project(user_id="user_alice", data=req)

    assert res.name == "Platform Services"
    assert res.slug == "platform-services"
    assert res.user_role == ProjectRole.OWNER
    assert res.member_count == 1
    mock_repos["proj_repo"].create.assert_called_once()
    mock_repos["member_repo"].create.assert_called_once()
    mock_repos["audit_repo"].log_event.assert_called_once()


@pytest.mark.asyncio
async def test_create_project_slug_collision_hex_suffix(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    # First call collides, second call with hex suffix succeeds
    existing_active = make_sample_project(name="Existing", slug="acme-project", status=ProjectStatus.ACTIVE)
    mock_repos["proj_repo"].get_by_slug.side_effect = [existing_active, None]

    created_proj = make_sample_project(name="Acme Project", slug="acme-project-a1b2")
    mock_repos["proj_repo"].create.return_value = created_proj
    mock_repos["member_repo"].create.return_value = MagicMock()
    mock_repos["audit_repo"].log_event.return_value = MagicMock()

    req = ProjectCreateRequest(name="Acme Project")
    res = await service.create_project(user_id="user_alice", data=req)

    assert res.slug == "acme-project-a1b2"
    assert mock_repos["proj_repo"].get_by_slug.call_count == 2


@pytest.mark.asyncio
async def test_create_project_explicit_slug_conflict(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    existing_active = make_sample_project(slug="existing-slug", status=ProjectStatus.ACTIVE)
    mock_repos["proj_repo"].get_by_slug.return_value = existing_active

    req = ProjectCreateRequest(name="My Project", slug="existing-slug")
    with pytest.raises(ConflictError) as exc_info:
        await service.create_project(user_id="user_alice", data=req)

    assert "slug already in use" in str(exc_info.value.message)


@pytest.mark.asyncio
async def test_get_project_tenant_isolation_non_member(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(owner_id="user_bob")
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    # user_charlie is not a member
    mock_repos["member_repo"].get_membership.return_value = None

    # Must raise NotFoundError, NOT ForbiddenError, to prevent tenant enumeration
    with pytest.raises(NotFoundError):
        await service.get_project(identifier=str(proj.id), user_id="user_charlie")


@pytest.mark.asyncio
async def test_get_project_success_for_member(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(owner_id="user_alice")
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    member = make_sample_member(proj.id, "user_alice", role=ProjectRole.OWNER)
    mock_repos["member_repo"].get_membership.return_value = member
    mock_repos["member_repo"].count_members.return_value = 3

    res = await service.get_project(identifier=str(proj.id), user_id="user_alice")
    assert res.id == str(proj.id)
    assert res.user_role == ProjectRole.OWNER
    assert res.member_count == 3


@pytest.mark.asyncio
async def test_update_project_occ_and_permissions(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(version=2)
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    member = make_sample_member(proj.id, "user_alice", role=ProjectRole.ADMIN)
    mock_repos["member_repo"].get_membership.return_value = member
    mock_repos["member_repo"].count_members.return_value = 2

    # OCC version mismatch
    req_bad_ver = ProjectUpdateRequest(name="New Name", version=1)
    with pytest.raises(ConflictError):
        await service.update_project(identifier=str(proj.id), user_id="user_alice", data=req_bad_ver)

    # VIEWER forbidden
    viewer_member = make_sample_member(proj.id, "user_viewer", role=ProjectRole.VIEWER)
    mock_repos["member_repo"].get_membership.return_value = viewer_member
    req_valid = ProjectUpdateRequest(name="New Name", version=2)
    with pytest.raises(ForbiddenError):
        await service.update_project(identifier=str(proj.id), user_id="user_viewer", data=req_valid)


@pytest.mark.asyncio
async def test_transfer_ownership_happy_path(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(owner_id="user_alice", version=1)
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    caller_member = make_sample_member(proj.id, "user_alice", role=ProjectRole.OWNER)
    target_member = make_sample_member(proj.id, "user_bob", role=ProjectRole.ADMIN)

    mock_repos["member_repo"].get_membership.side_effect = [caller_member, target_member]
    updated_proj = make_sample_project(owner_id="user_bob", version=2)
    mock_repos["proj_repo"].update_with_version.return_value = updated_proj
    mock_repos["member_repo"].count_members.return_value = 2

    req = TransferOwnershipRequest(new_owner_user_id="user_bob", former_owner_role=ProjectRole.ADMIN)
    res = await service.transfer_ownership(str(proj.id), "user_alice", req)

    assert res.owner_id == "user_bob"
    assert res.version == 2
    mock_repos["proj_repo"].update_with_version.assert_called_once()
    assert target_member.role == ProjectRole.OWNER
    assert caller_member.role == ProjectRole.ADMIN
    mock_repos["audit_repo"].log_event.assert_called_once()


@pytest.mark.asyncio
async def test_fsm_archive_and_unarchive(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(status=ProjectStatus.ACTIVE, version=1)
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    member = make_sample_member(proj.id, "user_admin", role=ProjectRole.ADMIN)
    mock_repos["member_repo"].get_membership.return_value = member

    archived_proj = make_sample_project(status=ProjectStatus.ARCHIVED, version=2)
    mock_repos["proj_repo"].transition_status.return_value = archived_proj

    res = await service.archive_project(str(proj.id), "user_admin")
    assert res.status == ProjectStatus.ARCHIVED
    mock_repos["proj_repo"].transition_status.assert_called_with(
        project_id=proj.id,
        from_state=ProjectStatus.ACTIVE,
        to_state=ProjectStatus.ARCHIVED,
        expected_version=1,
        additional_updates={"archived_at": pytest.approx(datetime.now(timezone.utc), abs=timedelta(seconds=5))},
    )

    # Unarchive
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = archived_proj
    active_proj = make_sample_project(status=ProjectStatus.ACTIVE, version=3)
    mock_repos["proj_repo"].transition_status.return_value = active_proj

    res_unarchive = await service.unarchive_project(str(proj.id), "user_admin")
    assert res_unarchive.status == ProjectStatus.ACTIVE


@pytest.mark.asyncio
async def test_fsm_illegal_transition_rejection(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(status=ProjectStatus.ACTIVE, version=1)
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    member = make_sample_member(proj.id, "user_owner", role=ProjectRole.OWNER)
    mock_repos["member_repo"].get_membership.return_value = member

    # Cannot purge directly from ACTIVE
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        await service.purge_project(str(proj.id), "user_owner")

    assert "Illegal project state transition from 'active' to 'purged'" in str(exc_info.value.message)


@pytest.mark.asyncio
async def test_fsm_soft_delete_and_restore(init_mock_beanie, mock_repos):
    service = ProjectService(
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(status=ProjectStatus.ACTIVE, version=1)
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    member = make_sample_member(proj.id, "user_owner", role=ProjectRole.OWNER)
    mock_repos["member_repo"].get_membership.return_value = member

    deleted_proj = make_sample_project(
        status=ProjectStatus.SOFT_DELETED,
        version=2,
        purge_after=datetime.now(timezone.utc) + timedelta(days=30),
    )
    mock_repos["proj_repo"].transition_status.return_value = deleted_proj

    res = await service.soft_delete_project(str(proj.id), "user_owner")
    assert res.status == ProjectStatus.SOFT_DELETED

    # Restore happy path
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = deleted_proj
    restored_proj = make_sample_project(status=ProjectStatus.ACTIVE, version=3)
    mock_repos["proj_repo"].transition_status.return_value = restored_proj

    res_restored = await service.restore_project(str(proj.id), "user_owner")
    assert res_restored.status == ProjectStatus.ACTIVE

    # Expired retention period rejects restore
    expired_proj = make_sample_project(
        status=ProjectStatus.SOFT_DELETED,
        version=2,
        purge_after=datetime.now(timezone.utc) - timedelta(days=1),
    )
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = expired_proj
    with pytest.raises(ProjectPurgedError):
        await service.restore_project(str(proj.id), "user_owner")


# ==============================================================================
# ProjectMemberService Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_add_member_admin_hierarchy_and_duplicate(init_mock_beanie, mock_repos):
    service = ProjectMemberService(
        member_repo=mock_repos["member_repo"],
        project_repo=mock_repos["proj_repo"],
        audit_repo=mock_repos["audit_repo"],
        user_repo=mock_repos["user_repo"],
    )

    proj = make_sample_project()
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    actor = make_sample_member(proj.id, "user_admin", role=ProjectRole.ADMIN)
    mock_repos["member_repo"].get_membership.side_effect = [actor, None]

    created = make_sample_member(proj.id, "user_new", role=ProjectRole.MEMBER)
    mock_repos["member_repo"].create.return_value = created

    # Valid add
    req = AddMemberRequest(user_id="user_new", role=ProjectRole.MEMBER)
    res = await service.add_member(str(proj.id), "user_admin", req)
    assert res.user_id == "user_new"

    # Cannot add as OWNER directly
    mock_repos["member_repo"].get_membership.side_effect = [actor]
    req_owner = AddMemberRequest.model_construct(user_id="user_owner_wannabe", role=ProjectRole.OWNER)
    with pytest.raises(BadRequestError):
        await service.add_member(str(proj.id), "user_admin", req_owner)


@pytest.mark.asyncio
async def test_update_member_role_admin_cannot_alter_admin_or_owner(init_mock_beanie, mock_repos):
    service = ProjectMemberService(
        member_repo=mock_repos["member_repo"],
        project_repo=mock_repos["proj_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(owner_id="user_owner")
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    admin_actor = make_sample_member(proj.id, "user_admin_1", role=ProjectRole.ADMIN)
    other_admin = make_sample_member(proj.id, "user_admin_2", role=ProjectRole.ADMIN)

    mock_repos["member_repo"].get_membership.side_effect = [admin_actor, other_admin]

    req = UpdateMemberRoleRequest(role=ProjectRole.MEMBER)
    # Admin cannot demote another Admin
    with pytest.raises(ForbiddenError) as exc_info:
        await service.update_member_role(str(proj.id), "user_admin_1", "user_admin_2", req)
    assert "ADMIN cannot modify roles of other ADMINs" in str(exc_info.value.message)


@pytest.mark.asyncio
async def test_remove_member_sole_owner_invariant(init_mock_beanie, mock_repos):
    service = ProjectMemberService(
        member_repo=mock_repos["member_repo"],
        project_repo=mock_repos["proj_repo"],
        audit_repo=mock_repos["audit_repo"],
    )

    proj = make_sample_project(owner_id="user_owner")
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj
    owner_member = make_sample_member(proj.id, "user_owner", role=ProjectRole.OWNER)
    mock_repos["member_repo"].get_membership.return_value = owner_member

    # Owner attempts self-leave
    with pytest.raises(ForbiddenError) as exc_info:
        await service.remove_member(str(proj.id), "user_owner", "user_owner")
    assert "The project OWNER cannot leave or be removed without transferring ownership first" in str(exc_info.value.message)


# ==============================================================================
# ProjectAuditService Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_audit_logs_role_restriction(init_mock_beanie, mock_repos):
    service = ProjectAuditService(
        audit_repo=mock_repos["audit_repo"],
        project_repo=mock_repos["proj_repo"],
        member_repo=mock_repos["member_repo"],
    )

    proj = make_sample_project()
    mock_repos["proj_repo"].get_by_id_or_slug.return_value = proj

    # VIEWER cannot access audit logs
    viewer = make_sample_member(proj.id, "user_viewer", role=ProjectRole.VIEWER)
    mock_repos["member_repo"].get_membership.return_value = viewer
    with pytest.raises(ForbiddenError):
        await service.list_audit_logs(str(proj.id), "user_viewer")

    # ADMIN can access audit logs
    admin = make_sample_member(proj.id, "user_admin", role=ProjectRole.ADMIN)
    mock_repos["member_repo"].get_membership.return_value = admin
    mock_repos["audit_repo"].list_events.return_value = ([], 0)

    logs, total = await service.list_audit_logs(str(proj.id), "user_admin")
    assert logs == []
    assert total == 0
