from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import ConflictError, InvalidStateTransitionError, NotFoundError
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectAuditLog,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
from app.repositories import (
    ProjectAuditRepository,
    ProjectMemberRepository,
    ProjectRepository,
    get_project_audit_repository,
    get_project_member_repository,
    get_project_repository,
)


@pytest.fixture
async def mock_beanie_db():
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])

    def get_collection(name):
        col = MagicMock()
        col.name = name
        col.create_index = AsyncMock()
        col.create_indexes = AsyncMock(return_value=[])
        col.index_information = AsyncMock(return_value={})
        col.find_one = AsyncMock(return_value=None)
        col.find_one_and_update = AsyncMock(return_value=None)
        col.count_documents = AsyncMock(return_value=0)
        col.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
        col.delete_many = AsyncMock(return_value=MagicMock(deleted_count=1))
        return col

    db.__getitem__.side_effect = get_collection
    await init_beanie(database=db, document_models=[Project, ProjectMember, ProjectAuditLog])
    return db


def test_di_factory_functions():
    proj_repo = get_project_repository()
    assert isinstance(proj_repo, ProjectRepository)

    member_repo = get_project_member_repository()
    assert isinstance(member_repo, ProjectMemberRepository)

    audit_repo = get_project_audit_repository()
    assert isinstance(audit_repo, ProjectAuditRepository)


async def test_project_repo_get_by_id_or_slug(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()

    # Mock get_by_id and get_by_slug
    with patch.object(repo, "get_by_id", new_callable=AsyncMock) as mock_get_id, \
         patch.object(repo, "get_by_slug", new_callable=AsyncMock) as mock_get_slug:

        dummy_project = Project(
            id=PydanticObjectId(test_id),
            name="Test Project",
            slug="test-proj",
            owner_id="user_owner",
        )
        mock_get_id.return_value = dummy_project

        # Calling with valid ObjectId str calls get_by_id first
        res = await repo.get_by_id_or_slug(str(test_id))
        assert res == dummy_project
        mock_get_id.assert_awaited_once_with(str(test_id))

        # Calling with non-ObjectId slug calls get_by_slug
        mock_get_id.reset_mock()
        mock_get_slug.return_value = dummy_project
        res2 = await repo.get_by_id_or_slug("test-proj")
        assert res2 == dummy_project
        mock_get_slug.assert_awaited_once_with("test-proj")


async def test_project_repo_create_duplicate_slug_raises_conflict(mock_beanie_db):
    repo = ProjectRepository()
    proj = Project(
        name="Collision Proj",
        slug="collision-proj",
        owner_id="user_owner",
    )
    with patch.object(Project, "insert", new_callable=AsyncMock) as mock_insert:
        mock_insert.side_effect = DuplicateKeyError("E11000 duplicate key error")
        with pytest.raises(ConflictError) as exc_info:
            await repo.create(proj)
        assert "already exists" in str(exc_info.value.message)


async def test_project_repo_update_with_version_occ_success(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()

    updated_doc = {
        "_id": test_id,
        "name": "Updated Name",
        "slug": "test-slug",
        "owner_id": "user_owner",
        "status": "active",
        "tags": [],
        "settings": {"default_environment": "production", "notifications_enabled": True, "retention_days": 30, "custom_settings": {}},
        "metadata": {},
        "version": 4,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    col.find_one_and_update = AsyncMock(return_value=updated_doc)

    res = await repo.update_with_version(
        project_id=PydanticObjectId(test_id),
        update_dict={"name": "Updated Name"},
        expected_version=3,
    )
    assert res.version == 4
    assert res.name == "Updated Name"


async def test_project_repo_update_with_version_occ_mismatch(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()
    col.find_one_and_update = AsyncMock(return_value=None)

    existing = Project(
        id=PydanticObjectId(test_id),
        name="Existing Name",
        slug="test-slug",
        owner_id="user_owner",
        version=4,  # mismatched, expected is 3
    )
    with patch.object(repo, "get_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = existing
        with pytest.raises(ConflictError) as exc_info:
            await repo.update_with_version(
                project_id=PydanticObjectId(test_id),
                update_dict={"name": "New Name"},
                expected_version=3,
            )
        assert "version conflict" in str(exc_info.value.message)


async def test_project_repo_transition_status_fsm_cas(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()

    updated_doc = {
        "_id": test_id,
        "name": "Test Project",
        "slug": "test-slug",
        "owner_id": "user_owner",
        "status": "archived",
        "tags": [],
        "settings": {"default_environment": "production", "notifications_enabled": True, "retention_days": 30, "custom_settings": {}},
        "metadata": {},
        "version": 2,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    col.find_one_and_update = AsyncMock(return_value=updated_doc)

    res = await repo.transition_status(
        project_id=PydanticObjectId(test_id),
        from_state=ProjectStatus.ACTIVE,
        to_state=ProjectStatus.ARCHIVED,
        expected_version=1,
    )
    assert res.status == ProjectStatus.ARCHIVED
    assert res.version == 2


async def test_project_repo_transition_status_illegal_transition(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()
    col.find_one_and_update = AsyncMock(return_value=None)

    existing = Project(
        id=PydanticObjectId(test_id),
        name="Test Project",
        slug="test-slug",
        owner_id="user_owner",
        status=ProjectStatus.ARCHIVED,  # already archived, but caller tried from ACTIVE
        version=1,
    )
    with patch.object(repo, "get_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = existing
        with pytest.raises(InvalidStateTransitionError) as exc_info:
            await repo.transition_status(
                project_id=PydanticObjectId(test_id),
                from_state=ProjectStatus.ACTIVE,
                to_state=ProjectStatus.SOFT_DELETED,
                expected_version=1,
            )
        assert "Illegal project state transition" in str(exc_info.value.message)


async def test_member_repo_create_duplicate_raises_conflict(mock_beanie_db):
    repo = ProjectMemberRepository()
    test_proj_id = ObjectId()
    member = ProjectMember(
        project_id=PydanticObjectId(test_proj_id),
        user_id="user_member",
        role=ProjectRole.MEMBER,
    )
    with patch.object(ProjectMember, "insert", new_callable=AsyncMock) as mock_insert:
        mock_insert.side_effect = DuplicateKeyError("E11000 duplicate key")
        with pytest.raises(ConflictError) as exc_info:
            await repo.create(member)
        assert "already a member" in str(exc_info.value.message)


async def test_member_repo_list_project_ids_for_user(mock_beanie_db):
    repo = ProjectMemberRepository()
    test_p1 = PydanticObjectId()
    test_p2 = PydanticObjectId()

    members = [
        ProjectMember(project_id=test_p1, user_id="user_123", role=ProjectRole.MEMBER),
        ProjectMember(project_id=test_p2, user_id="user_123", role=ProjectRole.ADMIN),
    ]
    with patch.object(repo, "find_many", new_callable=AsyncMock) as mock_find:
        mock_find.return_value = members
        ids = await repo.list_project_ids_for_user("user_123")
        assert ids == [test_p1, test_p2]


async def test_audit_repo_log_event(mock_beanie_db):
    repo = ProjectAuditRepository()
    test_pid = ObjectId()

    with patch.object(repo, "create", new_callable=AsyncMock) as mock_create:
        dummy_entry = MagicMock()
        mock_create.return_value = dummy_entry

        res = await repo.log_event(
            project_id=PydanticObjectId(test_pid),
            actor_id="user_admin",
            action=ProjectAuditAction.PROJECT_CREATED,
            payload={"name": "Initial Name"},
        )
        assert res == dummy_entry
        mock_create.assert_awaited_once()


async def test_project_repo_list_by_ids(mock_beanie_db):
    repo = ProjectRepository()
    id1 = PydanticObjectId()
    id2 = PydanticObjectId()

    proj1 = Project(id=id1, name="Alpha", slug="alpha", owner_id="user1", tags=["tag1"])
    proj2 = Project(id=id2, name="Beta", slug="beta", owner_id="user2", tags=["tag2"])

    with patch.object(repo, "count", new_callable=AsyncMock) as mock_count, \
         patch.object(repo, "find_many", new_callable=AsyncMock) as mock_find_many:
        mock_count.return_value = 2
        mock_find_many.return_value = [proj1, proj2]

        items, total = await repo.list_by_ids(
            project_ids=[id1, id2],
            status=ProjectStatus.ACTIVE,
            search="alp",
            tags=["tag1"],
            sort_by="name",
            sort_order="asc",
            skip=0,
            limit=10,
        )
        assert total == 2
        assert len(items) == 2
        mock_find_many.assert_awaited_once()
        # Verify query structure passed to find_many
        call_args = mock_find_many.call_args
        query_passed = call_args[0][0]
        assert query_passed["status"] == "active"
        assert query_passed["tags"] == {"$in": ["tag1"]}
        assert "$or" in query_passed
        assert call_args[1]["sort"] == "+name"


async def test_project_repo_update_with_version_not_found(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()
    col.find_one_and_update = AsyncMock(return_value=None)

    with patch.object(repo, "get_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = None
        with pytest.raises(NotFoundError) as exc_info:
            await repo.update_with_version(
                project_id=PydanticObjectId(test_id),
                update_dict={"name": "New Name"},
                expected_version=1,
            )
        assert f"Project '{test_id}' not found" in str(exc_info.value.message)


async def test_project_repo_transition_status_not_found(mock_beanie_db):
    repo = ProjectRepository()
    test_id = ObjectId()
    col = repo.get_collection()
    col.find_one_and_update = AsyncMock(return_value=None)

    with patch.object(repo, "get_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = None
        with pytest.raises(NotFoundError):
            await repo.transition_status(
                project_id=PydanticObjectId(test_id),
                from_state=ProjectStatus.ACTIVE,
                to_state=ProjectStatus.ARCHIVED,
                expected_version=1,
            )


async def test_member_repo_list_members_with_pagination_obj(mock_beanie_db):
    repo = ProjectMemberRepository()
    test_pid = ObjectId()

    class MockPaginationParams:
        offset = 15
        limit = 10

    with patch.object(repo, "count", new_callable=AsyncMock) as mock_count, \
         patch.object(repo, "find_many", new_callable=AsyncMock) as mock_find_many:
        mock_count.return_value = 50
        mock_find_many.return_value = []

        items, total = await repo.list_members(test_pid, skip=MockPaginationParams())
        assert total == 50
        assert items == []
        mock_find_many.assert_awaited_once_with(
            {"project_id": test_pid},
            skip=15,
            limit=10,
            sort="+joined_at",
        )


async def test_member_repo_delete_by_project_id(mock_beanie_db):
    repo = ProjectMemberRepository()
    test_pid = ObjectId()
    col = repo.get_collection()
    col.delete_many = AsyncMock(return_value=MagicMock(deleted_count=5))

    count = await repo.delete_by_project_id(test_pid)
    assert count == 5
    col.delete_many.assert_awaited_once_with({"project_id": test_pid}, session=None)


async def test_audit_repo_list_events(mock_beanie_db):
    repo = ProjectAuditRepository()
    test_pid = ObjectId()

    with patch.object(repo, "count", new_callable=AsyncMock) as mock_count, \
         patch.object(repo, "find_many", new_callable=AsyncMock) as mock_find_many:
        mock_count.return_value = 3
        mock_find_many.return_value = [MagicMock(), MagicMock(), MagicMock()]

        items, total = await repo.list_events(test_pid, skip=0, limit=20)
        assert total == 3
        assert len(items) == 3
        mock_find_many.assert_awaited_once_with(
            {"project_id": test_pid},
            skip=0,
            limit=20,
            sort="-created_at",
        )
