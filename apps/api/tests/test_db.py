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
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])
    col = MagicMock()
    col.name = "test_items"
    col.create_index = AsyncMock()
    col.index_information = AsyncMock(return_value={})
    db.__getitem__.return_value = col
    await init_beanie(database=db, document_models=[SampleItem])
    return db


async def test_base_document_metadata(init_mock_beanie):
    item = SampleItem(name="Test Item")
    assert item.name == "Test Item"
    assert item.created_at is not None
    assert item.updated_at is not None
    assert SampleItem.get_settings().is_root is False
    assert BaseDocument.get_settings().is_root is True


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
