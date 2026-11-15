from datetime import datetime, timezone, timedelta
from typing import Optional
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import jwt
import pytest

from app.core.config import settings
from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    ConfigurationError,
    UnauthorizedError,
)
from app.core.security import verify_clerk_token
from app.main import app, lifespan
from app.models.user import User, UserAuditAction, UserAuditLog, UserRole
from app.schemas.auth import AuthenticatedUser
from app.services.user_service import UserService


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


# --- AUTH-02 through AUTH-11 Test Cases ---


class InMemoryUserRepository:
    """In-memory UserRepository fake for isolated unit/domain tests."""

    def __init__(self, users: Optional[list] = None):
        self.users = {u.clerk_id: u for u in (users or [])}
        self.audit_logs: list = []
        self.bootstrap_claimed = False

    def is_db_ready(self) -> bool:
        return True

    async def get_by_clerk_id(self, clerk_id: str) -> Optional[User]:
        return self.users.get(clerk_id)

    async def get_by_email(self, email: str) -> Optional[User]:
        for u in self.users.values():
            if u.email == email:
                return u
        return None

    async def count_all(self) -> int:
        return len(self.users)

    async def count_active_admins(self) -> int:
        return sum(1 for u in self.users.values() if u.role == UserRole.ADMIN and u.is_active)

    async def create(self, user: User) -> User:
        self.users[user.clerk_id] = user
        return user

    async def update_profile_atomic(
        self,
        clerk_id: str,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        image_url: Optional[str] = None,
    ) -> Optional[User]:
        user = self.users.get(clerk_id)
        if not user:
            return None
        if email is not None:
            user.email = email
        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name
        if image_url is not None:
            user.image_url = image_url
        user.revision += 1
        return user

    async def update_role_atomic(
        self,
        clerk_id: str,
        new_role: UserRole,
        expected_role: Optional[UserRole] = None,
    ) -> Optional[User]:
        user = self.users.get(clerk_id)
        if not user:
            return None
        if expected_role and user.role != expected_role:
            return None
        user.role = new_role
        user.revision += 1
        return user

    async def update_status_atomic(self, clerk_id: str, is_active: bool) -> Optional[User]:
        user = self.users.get(clerk_id)
        if not user:
            return None
        user.is_active = is_active
        user.revision += 1
        return user

    async def claim_bootstrap_admin(self, clerk_id: str) -> bool:
        if not self.bootstrap_claimed:
            self.bootstrap_claimed = True
            return True
        return False

    async def record_audit_log(self, audit_log: UserAuditLog) -> UserAuditLog:
        self.audit_logs.append(audit_log)
        return audit_log


def test_auth_me_has_no_store_cache_control(client: TestClient, auth_headers: dict):
    """AUTH-11: GET /auth/me must set Cache-Control: no-store to prevent leaking PII."""
    response = client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert "no-store" in response.headers.get("cache-control", "").lower()


def test_update_role_rejects_invalid_clerk_id_regex(client: TestClient, admin_auth_headers: dict):
    """AUTH-11: clerk_id path param must match ^user_[A-Za-z0-9]+$ pattern."""
    response = client.put(
        "/api/v1/auth/users/not-valid-clerk-id/role",
        headers=admin_auth_headers,
        json={"role": "admin"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_role_safety_rails_and_audit(tool_models):
    """
    AUTH-02:
    - Last-admin demotion rejected (409 Conflict)
    - Self-demotion rejected (409 Conflict)
    - Successful role promotion writes immutable audit log
    """
    admin_user = User(clerk_id="user_admin_1", role=UserRole.ADMIN, is_active=True)
    target_user = User(clerk_id="user_target_1", role=UserRole.USER, is_active=True)
    fake_repo = InMemoryUserRepository([admin_user, target_user])
    service = UserService(user_repo=fake_repo)  # type: ignore[arg-type]

    admin_actor = AuthenticatedUser(
        id="oid_1",
        clerk_id="user_admin_1",
        role=UserRole.ADMIN,
    )

    # 1. Promote target to admin -> success and audit log emitted
    updated = await service.update_role(
        actor=admin_actor,
        clerk_id="user_target_1",
        new_role=UserRole.ADMIN,
        request_id="req_test_123",
        ip_address="127.0.0.1",
    )
    assert updated.role == UserRole.ADMIN
    assert len(fake_repo.audit_logs) == 1
    assert fake_repo.audit_logs[0].action == UserAuditAction.ROLE_UPDATED
    assert fake_repo.audit_logs[0].actor_id == "user_admin_1"
    assert fake_repo.audit_logs[0].target_clerk_id == "user_target_1"
    assert fake_repo.audit_logs[0].old_value == "user"
    assert fake_repo.audit_logs[0].new_value == "admin"

    # 2. Self-demotion rejected
    with pytest.raises(ConflictError) as exc_info:
        await service.update_role(
            actor=admin_actor,
            clerk_id="user_admin_1",
            new_role=UserRole.USER,
        )
    assert "Self-demotion is not permitted" in str(exc_info.value)

    # Demote user_target_1 back to user so only 1 admin remains
    admin_actor_2 = AuthenticatedUser(id="oid_2", clerk_id="user_target_1", role=UserRole.ADMIN)
    await service.update_role(actor=admin_actor, clerk_id="user_target_1", new_role=UserRole.USER)
    assert await fake_repo.count_active_admins() == 1

    # 3. Last admin demotion rejected
    with pytest.raises(ConflictError) as exc_info:
        await service.update_role(
            actor=admin_actor_2,
            clerk_id="user_admin_1",
            new_role=UserRole.USER,
        )
    assert "Cannot demote the last remaining active administrator" in str(exc_info.value)


@pytest.mark.asyncio
async def test_update_role_inactive_user_rejected(tool_models):
    """AUTH-02 & AUTH-04: Cannot promote or demote an inactive user."""
    admin_user = User(clerk_id="user_admin_1", role=UserRole.ADMIN, is_active=True)
    banned_user = User(clerk_id="user_banned_1", role=UserRole.USER, is_active=False)
    fake_repo = InMemoryUserRepository([admin_user, banned_user])
    service = UserService(user_repo=fake_repo)  # type: ignore[arg-type]

    admin_actor = AuthenticatedUser(id="oid_1", clerk_id="user_admin_1", role=UserRole.ADMIN)

    with pytest.raises(BadRequestError) as exc_info:
        await service.update_role(actor=admin_actor, clerk_id="user_banned_1", new_role=UserRole.ADMIN)
    assert "Cannot change role of an inactive user" in str(exc_info.value)


@pytest.mark.asyncio
async def test_sync_clerk_user_never_overwrites_role(tool_models):
    """
    AUTH-03 (Lost update prevention):
    sync_clerk_user only mutates profile fields (first_name, email, etc.)
    and never overwrites role.
    """
    existing_admin = User(
        clerk_id="user_occ_1",
        email="admin@example.com",
        first_name="Alice",
        role=UserRole.ADMIN,
        is_active=True,
    )
    fake_repo = InMemoryUserRepository([existing_admin])
    service = UserService(user_repo=fake_repo)  # type: ignore[arg-type]

    # Concurrent profile sync with updated first_name
    synced = await service.sync_clerk_user(
        clerk_id="user_occ_1",
        email="admin@example.com",
        first_name="Alice Updated",
    )
    assert synced is not None
    assert synced.first_name == "Alice Updated"
    assert synced.role == UserRole.ADMIN  # Role is safely preserved!


@pytest.mark.asyncio
async def test_update_status_and_deactivation_safety_rails(tool_models):
    """
    AUTH-04:
    - Admin can activate and deactivate regular users with audit log.
    - Admin cannot deactivate themselves.
    - Admin cannot deactivate the last active admin.
    """
    admin_1 = User(clerk_id="user_admin_1", role=UserRole.ADMIN, is_active=True)
    target = User(clerk_id="user_target_1", role=UserRole.USER, is_active=True)
    fake_repo = InMemoryUserRepository([admin_1, target])
    service = UserService(user_repo=fake_repo)  # type: ignore[arg-type]

    admin_actor = AuthenticatedUser(id="oid_1", clerk_id="user_admin_1", role=UserRole.ADMIN)

    # Deactivate target user
    updated = await service.update_status(actor=admin_actor, clerk_id="user_target_1", is_active=False)
    assert updated.is_active is False
    assert len(fake_repo.audit_logs) == 1
    assert fake_repo.audit_logs[0].action == UserAuditAction.STATUS_UPDATED
    assert fake_repo.audit_logs[0].new_value == "False"

    # Self-deactivation rejected
    with pytest.raises(ConflictError) as exc_info:
        await service.update_status(actor=admin_actor, clerk_id="user_admin_1", is_active=False)
    assert "Self-deactivation is not permitted" in str(exc_info.value)

    # Deactivating last active admin rejected
    admin_actor_other = AuthenticatedUser(id="oid_other", clerk_id="user_other_admin", role=UserRole.ADMIN)
    with pytest.raises(ConflictError) as exc_info:
        await service.update_status(actor=admin_actor_other, clerk_id="user_admin_1", is_active=False)
    assert "Cannot deactivate the last remaining active administrator" in str(exc_info.value)


@pytest.mark.asyncio
async def test_first_user_admin_bootstrap_one_shot(tool_models):
    """
    AUTH-05: Initial admin bootstrap is one-shot and race-free.
    First caller claims admin status; subsequent callers receive USER.
    """
    fake_repo = InMemoryUserRepository([])
    service = UserService(user_repo=fake_repo)  # type: ignore[arg-type]

    # First user logs in
    user_1 = await service.sync_clerk_user(clerk_id="user_first", email="first@example.com")
    assert user_1 is not None
    assert user_1.role == UserRole.ADMIN

    # Second concurrent or subsequent user logs in
    user_2 = await service.sync_clerk_user(clerk_id="user_second", email="second@example.com")
    assert user_2 is not None
    assert user_2.role == UserRole.USER



@pytest.mark.asyncio
async def test_production_startup_rejects_placeholder_clerk_key():
    """
    AUTH-06: In production, application lifespan fails closed if CLERK_SECRET_KEY
    is placeholder or unset.
    """
    with (
        patch.object(settings, "ENVIRONMENT", "production"),
        patch.object(settings, "CLERK_SECRET_KEY", "sk_test_placeholder_secret"),
        patch.object(settings, "DEBUG", False),
    ):
        with pytest.raises(ConfigurationError) as exc_info:
            async with lifespan(app):
                pass
        assert "CLERK_SECRET_KEY must be configured" in str(exc_info.value)


def test_authenticated_user_roles_derived_consistently_from_role():
    """AUTH-10: Schema derives 'roles' automatically and consistently from 'role'."""
    user = AuthenticatedUser(
        id="oid_1",
        clerk_id="user_1",
        role=UserRole.ADMIN,
        roles=["untrusted_token_claim_user"],  # Stale or conflicting claim
    )
    # Model validator forces consistency with authoritative role
    assert user.roles == ["admin"]



