"""Contract tests: FastAPI security schemes must match how the endpoints actually authenticate.

Regression: MOD-07 routes were added without the OpenAPI export being regenerated, and the
end-user session token was read with ``Header(...)`` instead of a security scheme, so
``openapi.json`` advertised 46 of 76 operations and never told clients that
``GET /projects/{project_id}/me`` needs ``X-Axion-End-User-Token``.
"""
from fastapi.testclient import TestClient

PUBLIC_OPERATIONS = {("get", "/health"), ("get", "/api/v1/health")}


def _spec(client: TestClient) -> dict:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    return response.json()


def test_openapi_declares_every_auth_scheme(client: TestClient):
    schemes = _spec(client)["components"]["securitySchemes"]

    assert set(schemes) == {"ClerkSession", "AxionApiKey", "EndUserSession"}
    assert schemes["ClerkSession"]["scheme"] == "bearer"
    assert schemes["ClerkSession"]["bearerFormat"] == "JWT"
    assert schemes["AxionApiKey"]["name"] == "X-Axion-Api-Key"
    assert schemes["AxionApiKey"]["in"] == "header"
    assert schemes["EndUserSession"]["name"] == "X-Axion-End-User-Token"
    assert schemes["EndUserSession"]["in"] == "header"


def test_end_user_token_route_declares_security_scheme(client: TestClient):
    operation = _spec(client)["paths"]["/api/v1/projects/{project_id}/me"]["get"]

    assert operation["security"] == [{"EndUserSession": []}]


def test_no_operation_silently_skips_the_security_contract(client: TestClient):
    spec = _spec(client)
    missing = {
        (method, path)
        for path, operations in spec["paths"].items()
        for method, operation in operations.items()
        if "security" not in operation
    }

    assert missing == PUBLIC_OPERATIONS
