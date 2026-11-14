from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from app.main import app


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
def invalid_auth_headers():
    return {"Authorization": "Bearer invalid-token"}
