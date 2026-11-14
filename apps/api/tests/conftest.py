import pytest
from fastapi.testclient import TestClient
from app.main import app


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
