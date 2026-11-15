import pytest
from unittest.mock import AsyncMock, MagicMock
from beanie import init_beanie
from app.api.deps import get_database, get_mongo_client
from app.core.exceptions import ServiceUnavailableError
from app.db.base import BaseDocument
from app.db.client import check_db_health


class SampleItem(BaseDocument):
    name: str

    class Settings:
        name = "test_items"


@pytest.fixture
async def init_mock_beanie():
    from bson import ObjectId
    from app.models.user import User

    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])
    col = MagicMock()
    col.name = "users"
    col.create_index = AsyncMock()
    col.create_indexes = AsyncMock(return_value=[])
    col.index_information = AsyncMock(return_value={})
    col.find_one = AsyncMock(return_value=None)
    col.count_documents = AsyncMock(return_value=0)
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
    db.__getitem__.return_value = col
    await init_beanie(database=db, document_models=[SampleItem, User])
    return db


async def test_base_document_metadata(init_mock_beanie):
    item = SampleItem(name="Test Item")
    assert item.name == "Test Item"
    assert item.created_at is not None
    assert item.updated_at is not None
    assert SampleItem.get_settings().is_root is False
    # BaseDocument must not be a root document: otherwise every model inherits
    # its collection and all documents/indexes get merged into "BaseDocument".
    assert BaseDocument.get_settings().is_root is False
    assert SampleItem.get_settings().name == "test_items"
    assert BaseDocument.get_settings().name != SampleItem.get_settings().name


async def test_check_db_health_uninitialized():
    res = await check_db_health(client=None)
    assert res["status"] == "disconnected"
    assert "error" in res


async def test_check_db_health_success():
    mock_client = MagicMock()
    mock_client.admin.command = AsyncMock(return_value={"ok": 1.0})
    res = await check_db_health(client=mock_client)
    assert res["status"] == "connected"
    assert "latency_ms" in res
    assert res["database"] == "axion"


def test_deps_raise_service_unavailable():
    mock_request = MagicMock()
    mock_request.app.state.mongo_client = None
    mock_request.app.state.mongo_db = None

    with pytest.raises(ServiceUnavailableError):
        get_mongo_client(mock_request)

    with pytest.raises(ServiceUnavailableError):
        get_database(mock_request)


def test_user_model_definition():
    from app.models.user import User, UserRole

    assert UserRole.ADMIN.value == "admin"
    assert UserRole.USER.value == "user"
    assert User.Settings.name == "users"
    assert len(User.Settings.indexes) >= 3


async def test_user_service_sync_first_user(init_mock_beanie):
    from app.models.user import UserRole
    from app.repositories.user_repository import UserRepository
    from app.services.user_service import UserService

    user_repo = UserRepository()
    service = UserService(user_repo=user_repo)
    user = await service.sync_clerk_user(
        clerk_id="user_admin_first",
        email="admin@example.com",
        first_name="Super",
        last_name="Admin",
    )
    assert user is not None
    assert user.clerk_id == "user_admin_first"
    assert user.role == UserRole.ADMIN


async def test_user_repository_and_service_with_mock():
    from app.models.user import User, UserRole
    from app.repositories.user_repository import UserRepository
    from app.services.user_service import UserService

    mock_repo = AsyncMock(spec=UserRepository)
    existing_user = User(
        clerk_id="user_mocked",
        email="mock@example.com",
        role=UserRole.USER,
    )
    admin_user = User(
        clerk_id="user_mocked",
        email="mock@example.com",
        role=UserRole.ADMIN,
    )
    mock_repo.get_by_clerk_id.return_value = existing_user
    mock_repo.update_role_atomic.return_value = admin_user
    mock_repo.is_db_ready.return_value = True

    service = UserService(user_repo=mock_repo)
    updated = await service.update_role("user_mocked", UserRole.ADMIN)

    assert updated is not None
    assert updated.role == UserRole.ADMIN
    mock_repo.update_role_atomic.assert_awaited_once_with(
        clerk_id="user_mocked",
        new_role=UserRole.ADMIN,
        expected_role=UserRole.USER,
    )
