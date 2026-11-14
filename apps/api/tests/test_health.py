from fastapi.testclient import TestClient


def test_root_health(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["success"] is True
    assert json_data["data"]["status"] == "ok"
    assert "version" in json_data["data"]
    assert "uptime_seconds" in json_data["data"]
    assert json_data["data"]["database"] == "connected"


def test_api_v1_health(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["success"] is True
    assert json_data["data"]["status"] == "ok"
    assert json_data["data"]["database"] == "connected"
