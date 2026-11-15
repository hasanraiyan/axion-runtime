from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from app.main import app


async def _bypass_rate_limit(self, request, call_next):
    return await call_next(request)


@pytest.fixture(autouse=True)
def disable_rate_limit_for_tests():
    with patch("app.middleware.rate_limit.InMemoryRateLimiterMiddleware.dispatch", new=_bypass_rate_limit):
        yield


@pytest.fixture(autouse=True)
def mock_db_operations():
    with (
        patch("app.main.init_db", new_callable=AsyncMock) as mock_init,
        patch("app.main.close_db", new_callable=AsyncMock) as mock_close,
        patch("app.services.health_service.check_db_health", new_callable=AsyncMock) as mock_health,
    ):
        mock_health.return_value = {"status": "connected", "latency_ms": 1.2, "database": "axion_test"}
        yield {
            "init": mock_init,
            "close": mock_close,
            "health": mock_health,
        }


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer dev-token-testuser"}


@pytest.fixture
def admin_auth_headers():
    return {"Authorization": "Bearer dev-token-admin_super"}


@pytest.fixture
def invalid_auth_headers():
    return {"Authorization": "Bearer invalid-token"}


@pytest.fixture
async def tool_models():
    """Initialize every Beanie document against a mocked database (no live MongoDB)."""
    from beanie import init_beanie
    from bson import ObjectId
    from unittest.mock import MagicMock

    from app.models import DOCUMENT_MODELS

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
        col.delete_many = AsyncMock(return_value=MagicMock(deleted_count=0))
        return col

    db.__getitem__.side_effect = get_collection

    # Beanie initialization is process-global. Remember each model's prior state and restore it afterwards
    # so these fixtures cannot change how unrelated tests behave (e.g. User sync falling back when the DB is
    # "uninitialized").
    # Beanie also stamps settings onto the shared base classes (BaseDocument, Document), so the whole
    # hierarchy must be restored, not just the concrete models.
    classes = {cls for model in DOCUMENT_MODELS for cls in model.__mro__ if "_document_settings" in dir(cls)}
    saved = {cls: cls.__dict__.get("_document_settings", "__unset__") for cls in classes}
    await init_beanie(database=db, document_models=list(DOCUMENT_MODELS))
    try:
        yield db
    finally:
        for model, previous in saved.items():
            if previous == "__unset__":
                if "_document_settings" in model.__dict__:
                    delattr(model, "_document_settings")
            else:
                model._document_settings = previous
