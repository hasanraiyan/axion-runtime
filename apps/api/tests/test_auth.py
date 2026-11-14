from fastapi.testclient import TestClient


def test_auth_me_unauthorized_without_header(client: TestClient):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    json_data = response.json()
    assert json_data["success"] is False
    assert json_data["error"]["code"] == "UNAUTHORIZED"
    assert "Missing Authorization header" in json_data["error"]["message"]


def test_auth_me_unauthorized_with_malformed_header(client: TestClient):
    response = client.get("/api/v1/auth/me", headers={"Authorization": "NotBearerToken"})
    assert response.status_code == 401
    json_data = response.json()
    assert json_data["success"] is False
    assert json_data["error"]["code"] == "UNAUTHORIZED"


def test_auth_me_authenticated_success(client: TestClient, auth_headers: dict):
    response = client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["success"] is True
    assert json_data["data"]["id"] == "user_testuser"
    assert json_data["data"]["email"] == "testuser@example.com"
