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


def test_auth_me_authenticated_user(client: TestClient, auth_headers: dict):
    response = client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["success"] is True
    assert json_data["data"]["clerk_id"] == "user_testuser"
    assert json_data["data"]["email"] == "testuser@example.com"
    assert json_data["data"]["role"] == "user"


def test_auth_me_authenticated_admin(client: TestClient, admin_auth_headers: dict):
    response = client.get("/api/v1/auth/me", headers=admin_auth_headers)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["success"] is True
    assert json_data["data"]["role"] == "admin"


def test_update_role_forbidden_for_regular_user(client: TestClient, auth_headers: dict):
    response = client.put(
        "/api/v1/auth/users/user_target/role",
        headers=auth_headers,
        json={"role": "admin"},
    )
    assert response.status_code == 403
    json_data = response.json()
    assert json_data["success"] is False
    assert json_data["error"]["code"] == "FORBIDDEN"


def test_update_role_not_found_for_admin(client: TestClient, admin_auth_headers: dict):
    response = client.put(
        "/api/v1/auth/users/user_nonexistent/role",
        headers=admin_auth_headers,
        json={"role": "user"},
    )
    assert response.status_code == 404
    json_data = response.json()
    assert json_data["success"] is False
    assert json_data["error"]["code"] == "NOT_FOUND"
