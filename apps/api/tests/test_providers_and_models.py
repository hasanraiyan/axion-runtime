"""
End-to-end integration and API tests for Provider & Model Management (MOD-06).
Verifies:
- FR-01: Provider registration and secret binding
- FR-02: Custom OpenAI-compatible configurations
- FR-03: Provider healthcheck handling (healthy, rate_limited, auth_failed, unreachable)
- FR-04: Dynamic model catalog discovery
- FR-05: Manual model registration
- FR-06: Model capability filtering
- FR-07: Resilient routing fallback resolution
- FR-08: OCC revision conflict (409) and soft delete
- FR-08: Secret unlink invariant (cannot delete secret if referenced by active provider)
- FR-09: Default provider and model switching
- FR-10: Cascading purge on project purge
- FR-11: Zero plaintext secret leakage
- FR-13: Live model inspection (pre-registration and live query)
- RBAC permission enforcement (Admin/Owner vs Viewer/Member)
- Tenant boundary isolation

Invariants:
- Zero live MongoDB dependency (mocked Beanie and in-memory fake repositories).
- Zero external network dependency (mocked httpx transport).
- Zero plaintext secret leakage across all responses.
"""
from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.api.deps import (
    get_current_user,
    get_model_catalog_service,
    get_model_routing_service,
    get_project_member_repository,
    get_project_model_repository,
    get_project_provider_repository,
    get_project_repository,
    get_project_routing_policy_repository,
    get_provider_service,
    get_secret_service,
)
from app.repositories.secret_repository import get_secret_repository
from app.core.crypto import CryptoService, EncryptedEnvelope
from app.core.exceptions import (
    SecretInUseError,
)
from app.main import app
from app.models import DOCUMENT_MODELS
from app.models.project import (
    Project,
    ProjectAuditLog,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
from app.models.project_model import ModelType, ProjectModel
from app.models.project_provider import (
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.models.project_routing_policy import ProjectRoutingPolicy
from app.models.secret import ProjectSecret
from app.models.user import UserRole
from app.schemas.auth import AuthenticatedUser
from app.schemas.routing_policy import ModelResolutionRequest, RoutingPolicyCreateRequest
from app.services.model_catalog_service import ModelCatalogService
from app.services.model_routing_service import ModelRoutingService
from app.services.project_service import ProjectService
from app.services.provider_service import ProviderManagementService
from app.services.secret_service import ProjectSecretService
from tests.fakes.fake_project_model_repository import FakeProjectModelRepository
from tests.fakes.fake_project_provider_repository import FakeProjectProviderRepository
from tests.fakes.fake_project_routing_policy_repository import FakeProjectRoutingPolicyRepository


# ==============================================================================
# Fixtures and Fakes Setup
# ==============================================================================


@pytest.fixture(autouse=True)
async def init_mock_beanie():
    """Mock Beanie ODM initialization with all document models."""
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
        col.delete_many = AsyncMock(return_value=MagicMock(deleted_count=1))
        return col

    db.__getitem__.side_effect = get_collection
    await init_beanie(
        database=db,
        document_models=DOCUMENT_MODELS,
    )
    return db


def make_user(user_id="user_admin", role=UserRole.USER):
    return AuthenticatedUser(
        id=user_id,
        clerk_id=user_id,
        email=f"{user_id}@example.com",
        first_name="Test",
        last_name="User",
        role=role,
        roles=[role.value],
        is_active=True,
        is_authenticated=True,
    )


class InMemoryAuditRepository:
    def __init__(self):
        self.logs: List[ProjectAuditLog] = []

    async def log_event(self, project_id, actor_id, action, payload=None):
        log = ProjectAuditLog(
            project_id=PydanticObjectId(str(project_id)),
            actor_id=actor_id,
            action=action,
            payload=payload or {},
        )
        log.id = PydanticObjectId()
        self.logs.append(log)
        return log


class InMemoryProjectRepositoryFake:
    def __init__(self):
        self.projects: Dict[str, Project] = {}

    async def get_by_id(self, project_id):
        return self.projects.get(str(project_id))

    async def get_by_id_or_slug(self, identifier):
        ident_str = str(identifier)
        for proj in self.projects.values():
            if str(proj.id) == ident_str or proj.slug == ident_str:
                return proj
        return None

    async def transition_status(self, project_id, from_state, to_state, expected_version, additional_updates=None):
        proj = self.projects.get(str(project_id))
        if proj:
            proj.status = to_state
            proj.version = expected_version + 1
            if additional_updates:
                for k, v in additional_updates.items():
                    setattr(proj, k, v)
        return proj

    async def purge(self, project_id):
        return self.projects.pop(str(project_id), None) is not None


class InMemoryProjectMemberRepositoryFake:
    def __init__(self):
        self.members: Dict[tuple[str, str], ProjectMember] = {}

    async def get_membership(self, project_id, user_id):
        return self.members.get((str(project_id), str(user_id)))

    async def delete_by_project_id(self, project_id):
        to_del = [k for k in self.members if k[0] == str(project_id)]
        for k in to_del:
            del self.members[k]
        return len(to_del)


class InMemorySecretRepositoryFake:
    def __init__(self):
        self.secrets: Dict[str, ProjectSecret] = {}

    async def get_by_id_and_project(self, secret_id, project_id, include_deleted=False):
        sec = self.secrets.get(str(secret_id))
        if sec and str(sec.project_id) == str(project_id):
            if not include_deleted and sec.is_deleted:
                return None
            return sec
        return None

    async def create(self, secret):
        if not hasattr(secret, "id") or secret.id is None:
            secret.id = PydanticObjectId()
        self.secrets[str(secret.id)] = secret
        return secret

    async def soft_delete(self, secret_id, project_id):
        sec = await self.get_by_id_and_project(secret_id, project_id)
        if sec:
            sec.is_deleted = True
            sec.deleted_at = datetime.now(timezone.utc)
            return True
        return False

    async def purge_by_project(self, project_id):
        to_del = [k for k, v in self.secrets.items() if str(v.project_id) == str(project_id)]
        for k in to_del:
            del self.secrets[k]
        return len(to_del)


def make_mock_transport(upstream_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if upstream_status == 200:
            if "generativelanguage" in url_str:
                return httpx.Response(200, json={
                    "models": [
                        {"name": "models/gemini-1.5-pro", "displayName": "Gemini 1.5 Pro"},
                        {"name": "models/gemini-1.5-flash", "displayName": "Gemini 1.5 Flash"},
                    ]
                })
            else:
                return httpx.Response(200, json={
                    "data": [
                        {"id": "gpt-4o", "display_name": "GPT-4o"},
                        {"id": "gpt-4o-mini", "display_name": "GPT-4o Mini"},
                        {"id": "text-embedding-3-small", "display_name": "Text Embedding 3 Small"},
                    ]
                })
        elif upstream_status == 429:
            return httpx.Response(429, json={"error": "Rate limit exceeded"})
        elif upstream_status in (401, 403):
            return httpx.Response(upstream_status, json={"error": "Unauthorized"})
        elif upstream_status == 500:
            return httpx.Response(500, json={"error": "Internal Server Error"})
        return httpx.Response(503, json={"error": "Unavailable"})

    return httpx.MockTransport(handler)


@pytest.fixture
def env():
    """Comprehensive environment fixture configuring all services and in-memory fakes."""
    project_id = "507f1f77bcf86cd799439011"
    proj_oid = ObjectId(project_id)

    # Active Project
    active_project = Project(
        name="Active AI Studio",
        slug="active-ai-studio",
        owner_id="user_owner",
        status=ProjectStatus.ACTIVE,
        version=1,
    )
    active_project.id = proj_oid

    # Repositories
    project_repo = InMemoryProjectRepositoryFake()
    project_repo.projects[project_id] = active_project

    member_repo = InMemoryProjectMemberRepositoryFake()
    admin_member = ProjectMember(project_id=proj_oid, user_id="user_admin", role=ProjectRole.ADMIN)
    owner_member = ProjectMember(project_id=proj_oid, user_id="user_owner", role=ProjectRole.OWNER)
    viewer_member = ProjectMember(project_id=proj_oid, user_id="user_viewer", role=ProjectRole.VIEWER)
    member_repo.members[(project_id, "user_admin")] = admin_member
    member_repo.members[(project_id, "user_owner")] = owner_member
    member_repo.members[(project_id, "user_viewer")] = viewer_member

    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    policy_repo = FakeProjectRoutingPolicyRepository()
    secret_repo = InMemorySecretRepositoryFake()
    audit_repo = InMemoryAuditRepository()

    # Secret
    secret_id = "507f1f77bcf86cd799439099"
    sample_secret = ProjectSecret(
        project_id=proj_oid,
        name="OPENAI_API_KEY",
        environment="production",
        created_by="user_admin",
        updated_by="user_admin",
        envelope=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
            ciphertext="Y2lwaGVydGV4dF9ieXRlcw==",
            nonce="MTIzNDU2Nzg5MDEy",
            auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            kek_id="local-v1",
        ),
        is_deleted=False,
    )
    sample_secret.id = PydanticObjectId(secret_id)
    secret_repo.secrets[secret_id] = sample_secret

    # Crypto Service
    crypto_service = MagicMock(spec=CryptoService)
    crypto_service.decrypt_secret = AsyncMock(return_value="sk-real-plaintext-secret-12345")
    crypto_service.encrypt_secret = AsyncMock(
        return_value=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
            ciphertext="Y2lwaGVydGV4dF9ieXRlcw==",
            nonce="MTIzNDU2Nzg5MDEy",
            auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            kek_id="local-v1",
        )
    )

    # HTTP Client with MockTransport
    http_client = httpx.AsyncClient(transport=make_mock_transport(200))

    # Services
    provider_service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=crypto_service,
        http_client=http_client,
    )

    model_service = ModelCatalogService(
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        provider_service=provider_service,
    )

    routing_service = ModelRoutingService(
        routing_policy_repo=policy_repo,
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
    )

    secret_service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=crypto_service,
        provider_repo=provider_repo,
    )

    # Dependency Overrides
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")
    app.dependency_overrides[get_project_repository] = lambda: project_repo
    app.dependency_overrides[get_project_member_repository] = lambda: member_repo
    app.dependency_overrides[get_project_provider_repository] = lambda: provider_repo
    app.dependency_overrides[get_project_model_repository] = lambda: model_repo
    app.dependency_overrides[get_project_routing_policy_repository] = lambda: policy_repo
    app.dependency_overrides[get_provider_service] = lambda: provider_service
    app.dependency_overrides[get_model_catalog_service] = lambda: model_service
    app.dependency_overrides[get_model_routing_service] = lambda: routing_service
    app.dependency_overrides[get_secret_repository] = lambda: secret_repo
    app.dependency_overrides[get_secret_service] = lambda: secret_service

    client = TestClient(app)

    yield {
        "project_id": project_id,
        "secret_id": secret_id,
        "client": client,
        "provider_service": provider_service,
        "model_service": model_service,
        "routing_service": routing_service,
        "secret_service": secret_service,
        "provider_repo": provider_repo,
        "model_repo": model_repo,
        "policy_repo": policy_repo,
        "secret_repo": secret_repo,
        "project_repo": project_repo,
        "member_repo": member_repo,
        "audit_repo": audit_repo,
        "crypto_service": crypto_service,
    }

    app.dependency_overrides.clear()


# ==============================================================================
# FR-01 & FR-11: Provider Registration, Secret Binding & Zero Plaintext
# ==============================================================================


def test_fr01_create_provider_success(env):
    """POST /projects/{project_id}/providers registers provider with secret binding and healthy status."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "Production OpenAI Provider",
        "slug": "prod-openai",
        "provider_type": "openai",
        "secret_id": sid,
        "timeout_seconds": 30,
        "max_retries": 2,
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code == status.HTTP_201_CREATED, resp.text
    data = resp.json()["data"]
    assert data["name"] == "Production OpenAI Provider"
    assert data["slug"] == "prod-openai"
    assert data["provider_type"] == "openai"
    assert data["secret_id"] == sid
    assert data["secret_name"] == "OPENAI_API_KEY"
    assert data["status"] == "active"
    assert data["healthcheck_status"] == "healthy"
    assert data["revision"] == 1

    # FR-11 Zero Plaintext Invariant: Decrypted secret must never be present in the response
    raw_response_text = resp.text
    assert "sk-real-plaintext-secret-12345" not in raw_response_text


def test_fr01_create_provider_secret_not_found(env):
    """POST /projects/{project_id}/providers fails with 404 when secret does not exist."""
    client = env["client"]
    pid = env["project_id"]
    non_existent_sid = "507f1f77bcf86cd799439999"

    payload = {
        "name": "Invalid Secret Provider",
        "provider_type": "openai",
        "secret_id": non_existent_sid,
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    err = resp.json()["error"]
    assert "not found" in err["message"].lower()


def test_fr01_create_provider_cross_tenant_secret(env):
    """Cross-tenant isolation: secret belonging to another project returns 404."""
    client = env["client"]
    pid = env["project_id"]

    # Create secret in a foreign project
    other_proj_id = ObjectId()
    foreign_sid = "507f1f77bcf86cd799439888"
    foreign_secret = ProjectSecret(
        project_id=other_proj_id,
        name="FOREIGN_KEY",
        environment="production",
        created_by="user_admin",
        updated_by="user_admin",
        envelope=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="dGVzdA==",
            ciphertext="dGVzdA==",
            nonce="dGVzdA==",
            auth_tag="dGVzdA==",
            kek_id="local-v1",
        ),
        is_deleted=False,
    )
    foreign_secret.id = PydanticObjectId(foreign_sid)
    env["secret_repo"].secrets[foreign_sid] = foreign_secret

    payload = {
        "name": "Cross Tenant Provider",
        "provider_type": "openai",
        "secret_id": foreign_sid,
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_fr01_create_provider_duplicate_slug_or_name(env):
    """POST /projects/{project_id}/providers rejects duplicate slug or name with 409 Conflict."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "Unique Provider",
        "slug": "unique-provider",
        "provider_type": "openai",
        "secret_id": sid,
    }

    resp1 = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp1.status_code == status.HTTP_201_CREATED

    # Duplicate slug
    resp2 = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp2.status_code == status.HTTP_409_CONFLICT
    assert resp2.json()["error"]["code"] in ("PROVIDER_SLUG_EXISTS", "CONFLICT_ERROR", "CONFLICT")


# ==============================================================================
# FR-02: Custom OpenAI-Compatible Configurations
# ==============================================================================


def test_fr02_custom_openai_compatible_success(env):
    """FR-02: Custom OpenAI-compatible provider with base_url and custom_headers."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "Self-Hosted vLLM",
        "slug": "vllm-cluster",
        "provider_type": "custom_openai_compatible",
        "secret_id": sid,
        "base_url": "http://vllm-node:8000/v1",
        "custom_headers": {
            "X-Tenant-Tag": "billing-enterprise",
            "HTTP-Referer": "https://axion.ai",
        },
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code == status.HTTP_201_CREATED, resp.text
    data = resp.json()["data"]
    assert data["provider_type"] == "custom_openai_compatible"
    assert data["base_url"] == "http://vllm-node:8000/v1"
    assert data["custom_headers"]["X-Tenant-Tag"] == "billing-enterprise"


def test_fr02_custom_provider_missing_base_url(env):
    """FR-02: Custom OpenAI-compatible provider requires base_url."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "Incomplete Custom Provider",
        "provider_type": "custom_openai_compatible",
        "secret_id": sid,
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)


def test_fr02_custom_provider_invalid_base_url(env):
    """FR-02: Custom provider base_url must start with http:// or https://."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "Malformed URL Provider",
        "provider_type": "custom_openai_compatible",
        "secret_id": sid,
        "base_url": "ftp://malformed-url.com",
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)


def test_fr02_custom_provider_crlf_injection(env):
    """FR-02: Custom headers reject newline injection."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    payload = {
        "name": "CRLF Injection Attempt",
        "provider_type": "custom_openai_compatible",
        "secret_id": sid,
        "base_url": "http://vllm-node:8000/v1",
        "custom_headers": {
            "X-Evil\r\nInjected-Header": "value",
        },
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers", json=payload)
    assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)


# ==============================================================================
# FR-03: Provider Healthcheck Handling
# ==============================================================================


@pytest.mark.parametrize(
    "upstream_status, expected_status, expected_healthcheck",
    [
        (200, "active", "healthy"),
        (429, "degraded", "rate_limited"),
        (401, "error", "auth_failed"),
        (503, "error", "unreachable"),
    ],
)
def test_fr03_provider_healthcheck_handling(env, upstream_status, expected_status, expected_healthcheck):
    """FR-03: Provider healthcheck handling under various upstream status codes."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    # 1. Create a provider
    create_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={
            "name": f"Healthcheck Test {upstream_status}",
            "slug": f"hc-{upstream_status}",
            "provider_type": "openai",
            "secret_id": sid,
        },
    )
    assert create_resp.status_code == status.HTTP_201_CREATED
    prov_id = create_resp.json()["data"]["id"]

    # 2. Swap provider service's HTTP client transport to simulate test status
    env["provider_service"].http_client = httpx.AsyncClient(transport=make_mock_transport(upstream_status))

    # 3. Call POST /providers/{provider_id}/test
    test_resp = client.post(f"/api/v1/projects/{pid}/providers/{prov_id}/test")
    assert test_resp.status_code == status.HTTP_200_OK
    data = test_resp.json()["data"]
    assert data["provider_id"] == prov_id
    assert data["status"] == expected_status
    assert data["healthcheck_status"] == expected_healthcheck

    # 4. GET /providers/{provider_id} verifies updated status in DB
    get_resp = client.get(f"/api/v1/projects/{pid}/providers/{prov_id}")
    assert get_resp.status_code == status.HTTP_200_OK
    assert get_resp.json()["data"]["status"] == expected_status
    assert get_resp.json()["data"]["healthcheck_status"] == expected_healthcheck


# ==============================================================================
# FR-04: Dynamic Model Catalog Discovery
# ==============================================================================


def test_fr04_dynamic_model_discovery(env):
    """FR-04: Dynamic upstream model discovery auto-registers models in project catalog."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    create_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={
            "name": "Discovery Provider",
            "slug": "discovery-prov",
            "provider_type": "openai",
            "secret_id": sid,
        },
    )
    assert create_resp.status_code == status.HTTP_201_CREATED
    prov_id = create_resp.json()["data"]["id"]

    env["provider_service"].http_client = httpx.AsyncClient(transport=make_mock_transport(200))

    disc_resp = client.post(f"/api/v1/projects/{pid}/providers/{prov_id}/discover")
    assert disc_resp.status_code == status.HTTP_200_OK, disc_resp.text
    summary = disc_resp.json()["data"]
    assert summary["provider_id"] == prov_id
    assert summary["discovered_count"] >= 2
    assert summary["created_count"] >= 2

    models_resp = client.get(f"/api/v1/projects/{pid}/models?provider_id={prov_id}")
    assert models_resp.status_code == status.HTTP_200_OK
    items = models_resp.json()["data"]["items"]
    model_ids = [m["model_id"] for m in items]
    assert "gpt-4o" in model_ids
    assert "gpt-4o-mini" in model_ids


# ==============================================================================
# FR-05: Manual Model Registration
# ==============================================================================


def test_fr05_manual_model_registration(env):
    """FR-05: Manual model registration under provider."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    create_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={
            "name": "Manual Provider",
            "slug": "manual-prov",
            "provider_type": "openai",
            "secret_id": sid,
        },
    )
    prov_id = create_resp.json()["data"]["id"]

    model_payload = {
        "provider_id": prov_id,
        "model_id": "custom-finetuned-llama3",
        "display_name": "Llama 3 8B Fine-tuned",
        "description": "Domain-specialized instruction model",
        "model_type": "chat_completion",
        "supports_streaming": True,
        "supports_tools": True,
        "supports_vision": False,
        "supports_json_mode": True,
        "max_input_tokens": 8192,
        "max_output_tokens": 2048,
        "input_cost_per_million": 0.50,
        "output_cost_per_million": 1.50,
    }

    resp = client.post(f"/api/v1/projects/{pid}/models", json=model_payload)
    assert resp.status_code == status.HTTP_201_CREATED, resp.text
    data = resp.json()["data"]
    assert data["model_id"] == "custom-finetuned-llama3"
    assert data["provider_id"] == prov_id
    assert data["supports_tools"] is True
    assert data["supports_vision"] is False
    assert data["max_input_tokens"] == 8192
    assert data["revision"] == 1


def test_fr05_duplicate_model_id_rejected(env):
    """FR-05: Duplicate model_id under the same provider raises 409 Conflict."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    create_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Dup Provider", "slug": "dup-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = create_resp.json()["data"]["id"]

    model_payload = {
        "provider_id": prov_id,
        "model_id": "model-alpha",
        "display_name": "Model Alpha",
        "model_type": "chat_completion",
    }

    resp1 = client.post(f"/api/v1/projects/{pid}/models", json=model_payload)
    assert resp1.status_code == status.HTTP_201_CREATED

    resp2 = client.post(f"/api/v1/projects/{pid}/models", json=model_payload)
    assert resp2.status_code == status.HTTP_409_CONFLICT
    assert resp2.json()["error"]["code"] in ("MODEL_EXISTS", "CONFLICT_ERROR", "CONFLICT")


# ==============================================================================
# FR-06: Model Capability Filtering
# ==============================================================================


def test_fr06_model_capability_filtering(env):
    """FR-06: Query models filtered by capability flags (tools, vision, JSON mode, modality)."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Cap Provider", "slug": "cap-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = prov_resp.json()["data"]["id"]

    # Model 1: Vision + Tools
    client.post(
        f"/api/v1/projects/{pid}/models",
        json={
            "provider_id": prov_id,
            "model_id": "vision-tool-model",
            "display_name": "Vision Tool Model",
            "model_type": "chat_completion",
            "supports_tools": True,
            "supports_vision": True,
        },
    )

    # Model 2: Tools only
    client.post(
        f"/api/v1/projects/{pid}/models",
        json={
            "provider_id": prov_id,
            "model_id": "text-tool-model",
            "display_name": "Text Tool Model",
            "model_type": "chat_completion",
            "supports_tools": True,
            "supports_vision": False,
        },
    )

    # Model 3: Embedding
    client.post(
        f"/api/v1/projects/{pid}/models",
        json={
            "provider_id": prov_id,
            "model_id": "embed-model",
            "display_name": "Embed Model",
            "model_type": "embedding",
            "supports_tools": False,
            "supports_vision": False,
        },
    )

    # Filter: supports_vision=True
    r_vision = client.get(f"/api/v1/projects/{pid}/models?supports_vision=true")
    assert r_vision.status_code == status.HTTP_200_OK
    items_v = r_vision.json()["data"]["items"]
    assert len(items_v) == 1
    assert items_v[0]["model_id"] == "vision-tool-model"

    # Filter: supports_tools=True
    r_tools = client.get(f"/api/v1/projects/{pid}/models?supports_tools=true")
    assert r_tools.status_code == status.HTTP_200_OK
    items_t = r_tools.json()["data"]["items"]
    assert len(items_t) == 2

    # Filter: model_type=embedding
    r_embed = client.get(f"/api/v1/projects/{pid}/models?model_type=embedding")
    assert r_embed.status_code == status.HTTP_200_OK
    items_e = r_embed.json()["data"]["items"]
    assert len(items_e) == 1
    assert items_e[0]["model_id"] == "embed-model"


# ==============================================================================
# FR-07: Resilient Routing Fallback Resolution
# ==============================================================================


@pytest.mark.asyncio
async def test_fr07_resilient_routing_fallback_resolution(env):
    """FR-07: Routing service falls back to backup model when primary provider is degraded."""
    pid = env["project_id"]
    routing_service = env["routing_service"]
    provider_repo = env["provider_repo"]
    model_repo = env["model_repo"]

    # 1. Primary Provider (Degraded)
    primary_prov = await provider_repo.create(
        ProjectProvider(
            project_id=PydanticObjectId(pid),
            name="Primary Provider",
            slug="prim-prov",
            provider_type=ProviderType.OPENAI,
            secret_id=PydanticObjectId(env["secret_id"]),
            status=ProviderStatus.DEGRADED,
            created_by="user_admin",
            updated_by="user_admin",
        )
    )

    # 2. Fallback Provider (Active)
    fallback_prov = await provider_repo.create(
        ProjectProvider(
            project_id=PydanticObjectId(pid),
            name="Fallback Provider",
            slug="fb-prov",
            provider_type=ProviderType.CUSTOM_OPENAI_COMPATIBLE,
            base_url="http://fallback:8000/v1",
            secret_id=PydanticObjectId(env["secret_id"]),
            status=ProviderStatus.ACTIVE,
            created_by="user_admin",
            updated_by="user_admin",
        )
    )

    # 3. Models
    primary_model = await model_repo.create(
        ProjectModel(
            project_id=PydanticObjectId(pid),
            provider_id=primary_prov.id,
            model_id="gpt-4o",
            display_name="GPT-4o",
            model_type=ModelType.CHAT_COMPLETION,
            is_enabled=True,
        )
    )

    fallback_model = await model_repo.create(
        ProjectModel(
            project_id=PydanticObjectId(pid),
            provider_id=fallback_prov.id,
            model_id="deepseek-chat",
            display_name="DeepSeek Chat",
            model_type=ModelType.CHAT_COMPLETION,
            is_enabled=True,
        )
    )

    # 4. Policy with primary -> fallback
    policy = await routing_service.create_policy(
        project_id=pid,
        request=RoutingPolicyCreateRequest(
            name="Resilient Policy",
            primary_model_id=str(primary_model.id),
            fallback_model_ids=[str(fallback_model.id)],
        ),
        actor_id="user_admin",
    )

    # 5. Resolve execution
    resolution = await routing_service.resolve_model(
        project_id=pid,
        request=ModelResolutionRequest(model_identifier=policy.name),
    )

    assert resolution.is_fallback is True
    assert resolution.upstream_model_id == "deepseek-chat"
    assert resolution.provider_type == "custom_openai_compatible"
    assert resolution.base_url == "http://fallback:8000/v1"


# ==============================================================================
# FR-08: OCC Revision Conflict (409) & Soft Deletion
# ==============================================================================


def test_fr08_provider_occ_revision_conflict(env):
    """FR-08: Provider PATCH rejects stale expected_revision with 409 Conflict."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "OCC Provider", "slug": "occ-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov = prov_resp.json()["data"]
    prov_id = prov["id"]
    assert prov["revision"] == 1

    # First update with revision=1 succeeds
    patch1 = client.patch(
        f"/api/v1/projects/{pid}/providers/{prov_id}",
        json={"name": "OCC Provider Updated", "revision": 1},
    )
    assert patch1.status_code == status.HTTP_200_OK
    assert patch1.json()["data"]["revision"] == 2

    # Second update sending stale revision=1 must fail with 409
    patch2 = client.patch(
        f"/api/v1/projects/{pid}/providers/{prov_id}",
        json={"name": "OCC Provider Stale", "revision": 1},
    )
    assert patch2.status_code == status.HTTP_409_CONFLICT
    assert patch2.json()["error"]["code"] == "REVISION_CONFLICT"


def test_fr08_model_occ_revision_conflict(env):
    """FR-08: Model PATCH rejects stale expected_revision with 409 Conflict."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Model OCC Prov", "slug": "model-occ", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = prov_resp.json()["data"]["id"]

    model_resp = client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": prov_id, "model_id": "occ-model", "display_name": "OCC Model", "model_type": "chat_completion"},
    )
    model_id = model_resp.json()["data"]["id"]
    assert model_resp.json()["data"]["revision"] == 1

    # First update succeeds
    patch1 = client.patch(
        f"/api/v1/projects/{pid}/models/{model_id}",
        json={"display_name": "Updated OCC Model", "revision": 1},
    )
    assert patch1.status_code == status.HTTP_200_OK
    assert patch1.json()["data"]["revision"] == 2

    # Stale revision fails
    patch2 = client.patch(
        f"/api/v1/projects/{pid}/models/{model_id}",
        json={"display_name": "Stale Update", "revision": 1},
    )
    assert patch2.status_code == status.HTTP_409_CONFLICT
    assert patch2.json()["error"]["code"] == "REVISION_CONFLICT"


def test_fr08_soft_delete_and_listing_exclusion(env):
    """FR-08: Soft-deleted providers and models are immediately excluded from active listings."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    # Create provider & model
    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Delete Me", "slug": "del-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = prov_resp.json()["data"]["id"]

    model_resp = client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": prov_id, "model_id": "del-model", "display_name": "Del Model", "model_type": "chat_completion"},
    )
    model_id = model_resp.json()["data"]["id"]

    # Delete Model
    del_m = client.delete(f"/api/v1/projects/{pid}/models/{model_id}")
    assert del_m.status_code == status.HTTP_200_OK

    # Verify model excluded from GET /models
    list_m = client.get(f"/api/v1/projects/{pid}/models?provider_id={prov_id}")
    assert list_m.status_code == status.HTTP_200_OK
    assert len(list_m.json()["data"]["items"]) == 0

    # Delete Provider
    del_p = client.delete(f"/api/v1/projects/{pid}/providers/{prov_id}")
    assert del_p.status_code == status.HTTP_200_OK

    # Verify provider excluded from GET /providers
    list_p = client.get(f"/api/v1/projects/{pid}/providers")
    assert list_p.status_code == status.HTTP_200_OK
    matching = [p for p in list_p.json()["data"]["items"] if p["id"] == prov_id]
    assert len(matching) == 0


# ==============================================================================
# FR-08: Secret Unlink Invariant
# ==============================================================================


@pytest.mark.asyncio
async def test_fr08_secret_unlink_invariant(env):
    """FR-08: Cannot delete secret if referenced by an active, non-deleted provider."""
    pid = env["project_id"]
    sid = env["secret_id"]
    provider_repo = env["provider_repo"]
    secret_service = env["secret_service"]

    # Create active provider referencing secret
    prov = await provider_repo.create(
        ProjectProvider(
            project_id=PydanticObjectId(pid),
            name="Bound Provider",
            slug="bound-prov",
            provider_type=ProviderType.OPENAI,
            secret_id=PydanticObjectId(sid),
            status=ProviderStatus.ACTIVE,
            created_by="user_admin",
            updated_by="user_admin",
        )
    )

    # Attempt to soft-delete secret -> must raise SecretInUseError
    with pytest.raises(SecretInUseError):
        await secret_service.delete_secret(pid, sid, actor_id="user_admin")

    # Soft-delete provider first
    await provider_repo.soft_delete(prov.id, pid)

    # Now secret deletion must succeed
    success = await secret_service.delete_secret(pid, sid, actor_id="user_admin")
    assert success is True


# ==============================================================================
# FR-09: Default Provider & Model Switching
# ==============================================================================


def test_fr09_default_provider_and_model_switching(env):
    """FR-09: Setting is_default=True atomically unsets previous default."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    # 1. Create first provider as default
    p1 = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Default Prov 1", "slug": "def-1", "provider_type": "openai", "secret_id": sid, "is_default": True},
    ).json()["data"]
    assert p1["is_default"] is True

    # 2. Create second provider as default
    p2 = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Default Prov 2", "slug": "def-2", "provider_type": "openai", "secret_id": sid, "is_default": True},
    ).json()["data"]
    assert p2["is_default"] is True

    # Verify first provider is no longer default
    p1_check = client.get(f"/api/v1/projects/{pid}/providers/{p1['id']}").json()["data"]
    assert p1_check["is_default"] is False

    # 3. Model default switching per model_type
    m1 = client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": p2["id"], "model_id": "chat-1", "display_name": "Chat 1", "model_type": "chat_completion", "is_default": True},
    ).json()["data"]
    assert m1["is_default"] is True

    m2 = client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": p2["id"], "model_id": "chat-2", "display_name": "Chat 2", "model_type": "chat_completion", "is_default": True},
    ).json()["data"]
    assert m2["is_default"] is True

    m1_check = client.get(f"/api/v1/projects/{pid}/models/{m1['id']}").json()["data"]
    assert m1_check["is_default"] is False


# ==============================================================================
# FR-10: Cascading Project Purge Integration
# ==============================================================================


@pytest.mark.asyncio
async def test_fr10_cascading_purge_on_project_purge(env):
    """FR-10: Permanent project purge cascades to models, providers, and routing policies."""
    pid = env["project_id"]
    provider_repo = env["provider_repo"]
    model_repo = env["model_repo"]
    policy_repo = env["policy_repo"]
    project_repo = env["project_repo"]
    audit_repo = env["audit_repo"]
    member_repo = env["member_repo"]
    secret_repo = env["secret_repo"]

    # Create provider, model, and policy
    prov = await provider_repo.create(
        ProjectProvider(
            project_id=PydanticObjectId(pid),
            name="Purge Prov",
            slug="purge-prov",
            provider_type=ProviderType.OPENAI,
            secret_id=PydanticObjectId(env["secret_id"]),
            created_by="user_admin",
            updated_by="user_admin",
        )
    )
    model = await model_repo.create(
        ProjectModel(
            project_id=PydanticObjectId(pid),
            provider_id=prov.id,
            model_id="purge-model",
            display_name="Purge Model",
            model_type=ModelType.CHAT_COMPLETION,
        )
    )
    policy = await policy_repo.create(
        ProjectRoutingPolicy(
            project_id=PydanticObjectId(pid),
            name="Purge Policy",
            primary_model_id=model.id,
        )
    )

    # Set project status to SOFT_DELETED so purge is allowed
    proj = await project_repo.get_by_id(pid)
    proj.status = ProjectStatus.SOFT_DELETED

    project_service = ProjectService(
        project_repo=project_repo,
        member_repo=member_repo,
        audit_repo=audit_repo,
        secret_repo=secret_repo,
        provider_repo=provider_repo,
        model_repo=model_repo,
        routing_policy_repo=policy_repo,
    )

    purge_res = await project_service.purge_project(pid, user_id="user_owner")
    assert purge_res["purged"] is True

    # Assert models, providers, and policies are completely removed
    assert await provider_repo.get_by_id_and_project(prov.id, pid, include_deleted=True) is None
    assert await model_repo.get_by_id_and_project(model.id, pid, include_deleted=True) is None
    assert await policy_repo.get_by_id_and_project(policy.id, pid) is None


# ==============================================================================
# FR-13: Live Model Inspection
# ==============================================================================


def test_fr13_inspect_models_pre_registration(env):
    """FR-13 Mode 1: POST /providers/inspect-models probes upstream using in-flight API key."""
    client = env["client"]
    pid = env["project_id"]

    env["provider_service"].http_client = httpx.AsyncClient(transport=make_mock_transport(200))

    payload = {
        "provider_type": "openai",
        "api_key": "sk-preview-key-only",
    }

    resp = client.post(f"/api/v1/projects/{pid}/providers/inspect-models", json=payload)
    assert resp.status_code == status.HTTP_200_OK, resp.text
    data = resp.json()["data"]
    assert data["provider_type"] == "openai"
    assert data["total_models"] >= 2
    model_ids = [m["model_id"] for m in data["models"]]
    assert "gpt-4o" in model_ids


def test_fr13_live_provider_models_saved_provider(env):
    """FR-13 Mode 2: GET /providers/{provider_id}/live-models queries upstream with saved secret."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Live Prov", "slug": "live-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = prov_resp.json()["data"]["id"]

    env["provider_service"].http_client = httpx.AsyncClient(transport=make_mock_transport(200))

    resp = client.get(f"/api/v1/projects/{pid}/providers/{prov_id}/live-models")
    assert resp.status_code == status.HTTP_200_OK, resp.text
    data = resp.json()["data"]
    assert data["total_models"] >= 2
    model_ids = [m["model_id"] for m in data["models"]]
    assert "gpt-4o" in model_ids



# ==============================================================================
# RBAC Permission Enforcement & Tenant Boundary Isolation
# ==============================================================================


def test_rbac_viewer_permissions(env):
    """RBAC: VIEWER can read providers and models, but cannot create, update, delete, or discover."""
    client = env["client"]
    pid = env["project_id"]
    sid = env["secret_id"]

    # 1. First, create a provider as ADMIN
    app.dependency_overrides[get_current_user] = lambda: make_user("user_admin")
    prov_resp = client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "RBAC Prov", "slug": "rbac-prov", "provider_type": "openai", "secret_id": sid},
    )
    prov_id = prov_resp.json()["data"]["id"]

    model_resp = client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": prov_id, "model_id": "rbac-model", "display_name": "RBAC Model", "model_type": "chat_completion"},
    )
    model_id = model_resp.json()["data"]["id"]

    # 2. Switch current user to VIEWER
    app.dependency_overrides[get_current_user] = lambda: make_user("user_viewer")

    # Read operations -> allowed (200)
    assert client.get(f"/api/v1/projects/{pid}/providers").status_code == status.HTTP_200_OK
    assert client.get(f"/api/v1/projects/{pid}/providers/{prov_id}").status_code == status.HTTP_200_OK
    assert client.get(f"/api/v1/projects/{pid}/models").status_code == status.HTTP_200_OK
    assert client.get(f"/api/v1/projects/{pid}/models/{model_id}").status_code == status.HTTP_200_OK

    # Mutation operations -> forbidden (403)
    assert client.post(
        f"/api/v1/projects/{pid}/providers",
        json={"name": "Forbidden", "provider_type": "openai", "secret_id": sid},
    ).status_code == status.HTTP_403_FORBIDDEN

    assert client.patch(
        f"/api/v1/projects/{pid}/providers/{prov_id}",
        json={"name": "Forbidden", "expected_revision": 1},
    ).status_code == status.HTTP_403_FORBIDDEN

    assert client.delete(f"/api/v1/projects/{pid}/providers/{prov_id}").status_code == status.HTTP_403_FORBIDDEN
    assert client.post(f"/api/v1/projects/{pid}/providers/{prov_id}/test").status_code == status.HTTP_403_FORBIDDEN
    assert client.post(f"/api/v1/projects/{pid}/providers/{prov_id}/discover").status_code == status.HTTP_403_FORBIDDEN
    assert client.post(
        f"/api/v1/projects/{pid}/models",
        json={"provider_id": prov_id, "model_id": "forbidden", "display_name": "F", "model_type": "chat_completion"},
    ).status_code == status.HTTP_403_FORBIDDEN
    assert client.patch(
        f"/api/v1/projects/{pid}/models/{model_id}",
        json={"display_name": "Forbidden", "expected_revision": 1},
    ).status_code == status.HTTP_403_FORBIDDEN
    assert client.delete(f"/api/v1/projects/{pid}/models/{model_id}").status_code == status.HTTP_403_FORBIDDEN


def test_tenant_boundary_isolation(env):
    """Tenant boundary: queries specifying unknown or foreign project_id return 404."""
    client = env["client"]
    foreign_pid = "507f1f77bcf86cd799439999"

    resp_p = client.get(f"/api/v1/projects/{foreign_pid}/providers")
    assert resp_p.status_code == status.HTTP_404_NOT_FOUND

    resp_m = client.get(f"/api/v1/projects/{foreign_pid}/models")
    assert resp_m.status_code == status.HTTP_404_NOT_FOUND
