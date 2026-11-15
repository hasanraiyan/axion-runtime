from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import jwt
import pytest

from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.core.security import verify_clerk_token


def _generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


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


# --- AUTH-01 Regression Tests: Official Clerk SDK Token Verification ---

@pytest.mark.asyncio
async def test_verify_clerk_token_accepts_valid_signed_token():
    private_key, public_pem = _generate_rsa_key_pair()
    token = jwt.encode(
        {
            "sub": "user_legit_123",
            "email": "legit@example.com",
            "first_name": "Legit",
            "last_name": "User",
            "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp(),
        },
        private_key,
        algorithm="RS256",
    )

    with patch.object(settings, "CLERK_JWT_KEY", public_pem):
        user = await verify_clerk_token(token)
        assert user.clerk_id == "user_legit_123"
        assert user.email == "legit@example.com"
        assert user.first_name == "Legit"
        assert user.last_name == "User"


@pytest.mark.asyncio
async def test_verify_clerk_token_rejects_unsigned_forged_token():
    """
    AUTH-01 regression: An attacker sends an unsigned JWT with algorithm 'none'
    or missing signature attempting to impersonate another user.
    The Clerk SDK must reject it.
    """
    _, public_pem = _generate_rsa_key_pair()
    forged_token = jwt.encode(
        {"sub": "user_victim_admin", "email": "admin@example.com"},
        key="",
        algorithm="none",
    )

    with patch.object(settings, "CLERK_JWT_KEY", public_pem):
        with pytest.raises(UnauthorizedError) as exc_info:
            await verify_clerk_token(forged_token)
        assert "Invalid or expired session token" in str(exc_info.value)


@pytest.mark.asyncio
async def test_verify_clerk_token_rejects_tampered_signature():
    """AUTH-01 regression: Token signed by an unknown/untrusted private key is rejected."""
    untrusted_private_key, _ = _generate_rsa_key_pair()
    _, trusted_public_pem = _generate_rsa_key_pair()

    tampered_token = jwt.encode(
        {"sub": "user_victim", "email": "victim@example.com"},
        untrusted_private_key,
        algorithm="RS256",
    )

    with patch.object(settings, "CLERK_JWT_KEY", trusted_public_pem):
        with pytest.raises(UnauthorizedError) as exc_info:
            await verify_clerk_token(tampered_token)
        assert "Invalid or expired session token" in str(exc_info.value)


@pytest.mark.asyncio
async def test_verify_clerk_token_rejects_expired_token():
    """AUTH-01 regression: An expired token must be rejected."""
    private_key, public_pem = _generate_rsa_key_pair()
    expired_token = jwt.encode(
        {
            "sub": "user_expired",
            "exp": (datetime.now(timezone.utc) - timedelta(hours=2)).timestamp(),
        },
        private_key,
        algorithm="RS256",
    )

    with patch.object(settings, "CLERK_JWT_KEY", public_pem):
        with pytest.raises(UnauthorizedError) as exc_info:
            await verify_clerk_token(expired_token)
        assert "Invalid or expired session token" in str(exc_info.value)


def test_auth_me_rejects_forged_token_end_to_end(client: TestClient):
    """AUTH-01 regression: End-to-end request with forged unsigned token returns 401."""
    _, public_pem = _generate_rsa_key_pair()
    forged_token = jwt.encode(
        {"sub": "user_target_admin", "email": "target@example.com"},
        key="",
        algorithm="none",
    )

    with patch.object(settings, "CLERK_JWT_KEY", public_pem):
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "UNAUTHORIZED"


# --- CLERK_SECRET_KEY Only (JWKS verification without CLERK_JWT_KEY) ---

@pytest.mark.asyncio
async def test_verify_clerk_token_with_secret_key_only_jwks():
    """Verify session token using only CLERK_SECRET_KEY via JWKS (no CLERK_JWT_KEY)."""
    from jwt.algorithms import RSAAlgorithm

    private_key, _ = _generate_rsa_key_pair()
    jwk_dict = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk_dict["kid"] = "clerk_active_key_1"

    token = jwt.encode(
        {
            "sub": "user_secret_only_123",
            "email": "secret_only@example.com",
            "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp(),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "clerk_active_key_1"},
    )

    with (
        patch.object(settings, "CLERK_SECRET_KEY", "sk_test_mock_secret_key_123"),
        patch.object(settings, "CLERK_JWT_KEY", None),
        patch("clerk_backend_api.security.verifytoken._fetch_jwks_async", return_value={"keys": [jwk_dict]}),
    ):
        user = await verify_clerk_token(token)
        assert user.clerk_id == "user_secret_only_123"
        assert user.email == "secret_only@example.com"


@pytest.mark.asyncio
async def test_verify_clerk_token_with_secret_key_only_rejects_forged_token():
    """Verify forged tokens are rejected when only CLERK_SECRET_KEY is configured."""
    forged_token = jwt.encode(
        {"sub": "user_victim_admin", "email": "admin@example.com"},
        key="",
        algorithm="none",
    )

    with (
        patch.object(settings, "CLERK_SECRET_KEY", "sk_test_mock_secret_key_123"),
        patch.object(settings, "CLERK_JWT_KEY", None),
    ):
        with pytest.raises(UnauthorizedError) as exc_info:
            await verify_clerk_token(forged_token)
        assert "Invalid or expired session token" in str(exc_info.value)


