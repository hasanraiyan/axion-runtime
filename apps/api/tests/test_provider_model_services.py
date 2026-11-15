"""
Unit and integration tests for Module 06 Services (SRS-06):
- ProviderManagementService (FR-01, FR-02, FR-03, FR-08, FR-09, FR-11, FR-13)
- ModelCatalogService (FR-04, FR-05, FR-06, FR-08, FR-09)
- ModelRoutingService (FR-07)
- Secret Unlink Invariant (FR-08) in ProjectSecretService
- Cascading Project Purge (FR-10) in ProjectService
"""
from unittest.mock import AsyncMock, MagicMock
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
import httpx
import pytest
from pydantic import SecretStr

from app.core.crypto import CryptoService, EncryptedEnvelope
from app.core.exceptions import (
    ConflictError,
    SecretInUseError,
)
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectRole,
    ProjectStatus,
)
from app.models.project_model import ModelType, ProjectModel
from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.models.project_routing_policy import ProjectRoutingPolicy
from app.models.secret import ProjectSecret
from app.schemas.model_catalog import (
    ModelCreateRequest,
)
from app.schemas.provider import (
    ProviderCreateRequest,
    ProviderInspectRequest,
    ProviderUpdateRequest,
)
from app.schemas.routing_policy import (
    ModelResolutionRequest,
    RoutingPolicyCreateRequest,
)
from app.services.model_catalog_service import ModelCatalogService
from app.services.model_routing_service import ModelRoutingService
from app.services.project_service import ProjectService
from app.services.provider_service import ProviderManagementService
from app.services.secret_service import ProjectSecretService
from tests.fakes.fake_project_model_repository import FakeProjectModelRepository
from tests.fakes.fake_project_provider_repository import FakeProjectProviderRepository
from tests.fakes.fake_project_routing_policy_repository import FakeProjectRoutingPolicyRepository


@pytest.fixture(autouse=True)
async def mock_beanie_db():
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
        document_models=[ProjectProvider, ProjectModel, ProjectRoutingPolicy, Project, ProjectSecret],
    )
    return db


@pytest.fixture
def mock_crypto():
    service = MagicMock(spec=CryptoService)
    service.decrypt_secret = AsyncMock(return_value="sk-decrypted-test-key-12345")
    service.encrypt_secret = AsyncMock(
        return_value=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
            ciphertext="Y2lwaGVydGV4dF9ieXRlcw==",
            nonce="MTIzNDU2Nzg5MDEy",
            auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            kek_id="local-v1",
        )
    )
    return service


@pytest.fixture
def active_project():
    proj = MagicMock(spec=Project)
    proj.id = PydanticObjectId()
    proj.name = "Active AI Project"
    proj.slug = "active-ai-project"
    proj.status = ProjectStatus.ACTIVE
    proj.version = 1
    proj.owner_id = "user_owner"
    return proj


@pytest.fixture
def sample_secret(active_project):
    sec = MagicMock(spec=ProjectSecret)
    sec.id = PydanticObjectId()
    sec.project_id = active_project.id
    sec.name = "OPENAI_API_KEY"
    sec.environment = "production"
    sec.is_deleted = False
    sec.envelope = MagicMock()
    return sec


# ==============================================================================
# ProviderManagementService Tests (FR-01, FR-02, FR-03, FR-08, FR-09, FR-11, FR-13)
# ==============================================================================


@pytest.mark.asyncio
async def test_create_provider_success(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    # Mock HTTP client for successful healthcheck probe
    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.is_success = True
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    req = ProviderCreateRequest(
        name="OpenAI Primary",
        slug="openai-primary",
        provider_type=ProviderType.OPENAI,
        secret_id=str(sample_secret.id),
        is_default=True,
    )

    result = await service.create_provider(active_project.id, req, actor_id="user_admin")

    assert result.name == "OpenAI Primary"
    assert result.slug == "openai-primary"
    assert result.status == ProviderStatus.ACTIVE
    assert result.healthcheck_status == HealthcheckStatus.HEALTHY
    assert result.is_default is True
    assert result.secret_id == str(sample_secret.id)
    assert result.secret_name == "OPENAI_API_KEY"
    assert result.revision == 1

    # Audit event verified
    audit_repo.log_event.assert_called_once()
    call_kwargs = audit_repo.log_event.call_args.kwargs
    assert call_kwargs["action"] == ProjectAuditAction.PROVIDER_CREATED


@pytest.mark.asyncio
async def test_create_provider_failed_healthcheck(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    # HTTP 401 Auth Failed probe
    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401
    mock_resp.is_success = False
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    req = ProviderCreateRequest(
        name="OpenAI Invalid Key",
        slug="openai-invalid",
        provider_type=ProviderType.OPENAI,
        secret_id=str(sample_secret.id),
    )

    result = await service.create_provider(active_project.id, req, actor_id="user_admin")
    assert result.status == ProviderStatus.ERROR
    assert result.healthcheck_status == HealthcheckStatus.AUTH_FAILED


@pytest.mark.asyncio
async def test_create_provider_duplicate_slug_or_name(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    req = ProviderCreateRequest(
        name="Unique Name",
        slug="unique-slug",
        provider_type=ProviderType.OPENAI,
        secret_id=str(sample_secret.id),
    )
    await service.create_provider(active_project.id, req, actor_id="user_admin")

    # Duplicate slug
    with pytest.raises(ConflictError):
        await service.create_provider(
            active_project.id,
            ProviderCreateRequest(
                name="Different Name",
                slug="unique-slug",
                provider_type=ProviderType.OPENAI,
                secret_id=str(sample_secret.id),
            ),
            actor_id="user_admin",
        )


@pytest.mark.asyncio
async def test_update_provider_occ_and_revision_increment(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    created = await service.create_provider(
        active_project.id,
        ProviderCreateRequest(
            name="DeepSeek Service",
            slug="deepseek-service",
            provider_type=ProviderType.CUSTOM_OPENAI_COMPATIBLE,
            base_url="https://api.deepseek.com/v1",
            secret_id=str(sample_secret.id),
        ),
        actor_id="user_1",
    )
    assert created.revision == 1

    # Valid update with expected revision=1
    updated = await service.update_provider(
        active_project.id,
        created.id,
        ProviderUpdateRequest(name="DeepSeek V3 Service", revision=1),
        actor_id="user_1",
    )
    assert updated.name == "DeepSeek V3 Service"
    assert updated.revision == 2

    # OCC conflict: expected revision=1 when current is 2
    with pytest.raises(ConflictError):
        await service.update_provider(
            active_project.id,
            created.id,
            ProviderUpdateRequest(name="Concurrent Update", revision=1),
            actor_id="user_2",
        )


@pytest.mark.asyncio
async def test_delete_provider_cascades_soft_delete_to_models(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    prov = await service.create_provider(
        active_project.id,
        ProviderCreateRequest(
            name="To Delete",
            slug="to-delete",
            provider_type=ProviderType.OPENAI,
            secret_id=str(sample_secret.id),
        ),
        actor_id="user_1",
    )

    # Add child model
    await model_repo.create(
        ProjectModel(
            project_id=active_project.id,
            provider_id=PydanticObjectId(prov.id),
            model_id="gpt-4o",
            display_name="GPT-4o",
        )
    )

    deleted = await service.delete_provider(active_project.id, prov.id, actor_id="user_1")
    assert deleted is True

    # Verify provider is soft deleted
    fetched_prov = await provider_repo.get_by_id_and_project(prov.id, active_project.id)
    assert fetched_prov is None

    # Verify child model is soft deleted
    models = await model_repo.list_by_provider(prov.id, include_deleted=False)
    assert len(models) == 0


@pytest.mark.asyncio
async def test_inspect_models_live_preview(active_project, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    model_repo = FakeProjectModelRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    secret_repo = MagicMock()
    audit_repo = MagicMock()

    # Mock upstream /models response
    http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.json = MagicMock(
        return_value={
            "data": [
                {"id": "gpt-4o", "display_name": "GPT-4o Multimodal"},
                {"id": "text-embedding-3-small", "display_name": "Text Embedding 3 Small"},
                {"id": "o1-mini", "display_name": "o1 Mini Reasoning"},
            ]
        }
    )
    http_client.get = AsyncMock(return_value=mock_resp)

    service = ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        http_client=http_client,
    )

    inspect_req = ProviderInspectRequest(
        provider_type=ProviderType.OPENAI,
        api_key=SecretStr("sk-transient-preview-key"),
    )

    result = await service.inspect_upstream_models(active_project.id, inspect_req)
    assert result.total_models == 3
    gpt4o = next(m for m in result.models if m.model_id == "gpt-4o")
    assert gpt4o.supports_vision is True
    assert gpt4o.supports_tools is True
    assert gpt4o.model_type == ModelType.CHAT_COMPLETION

    embed = next(m for m in result.models if m.model_id == "text-embedding-3-small")
    assert embed.model_type == ModelType.EMBEDDING
    assert embed.supports_streaming is False


# ==============================================================================
# ModelCatalogService Tests (FR-04, FR-05, FR-06, FR-08, FR-09)
# ==============================================================================


@pytest.mark.asyncio
async def test_create_model_and_capability_query(active_project):
    model_repo = FakeProjectModelRepository()
    provider_repo = FakeProjectProviderRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()
    audit_repo.log_event = AsyncMock()

    # Create dummy provider
    prov = await provider_repo.create(
        ProjectProvider(
            project_id=active_project.id,
            name="OpenAI Service",
            slug="openai-service",
            provider_type=ProviderType.OPENAI,
            secret_id=PydanticObjectId(),
            created_by="admin",
            updated_by="admin",
        )
    )

    catalog_service = ModelCatalogService(
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
    )

    req = ModelCreateRequest(
        provider_id=str(prov.id),
        model_id="gpt-4o",
        display_name="GPT-4o Frontier",
        supports_vision=True,
        supports_tools=True,
        supports_json_mode=True,
        max_input_tokens=128000,
        max_output_tokens=4096,
        is_default=True,
    )

    created = await catalog_service.create_model(active_project.id, req, actor_id="admin")
    assert created.model_id == "gpt-4o"
    assert created.supports_vision is True
    assert created.is_default is True
    assert created.revision == 1

    # Duplicate model_id under same provider
    with pytest.raises(ConflictError):
        await catalog_service.create_model(active_project.id, req, actor_id="admin")

    # Capability filter query (FR-06)
    models_with_vision, total = await catalog_service.list_models(
        active_project.id, supports_vision=True
    )
    assert total == 1
    assert models_with_vision[0].model_id == "gpt-4o"

    models_without_vision, total_empty = await catalog_service.list_models(
        active_project.id, supports_vision=False
    )
    assert total_empty == 0


@pytest.mark.asyncio
async def test_model_catalog_discovery(active_project):
    model_repo = FakeProjectModelRepository()
    provider_repo = FakeProjectProviderRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()
    audit_repo.log_event = AsyncMock()

    prov = await provider_repo.create(
        ProjectProvider(
            project_id=active_project.id,
            name="Google Gemini",
            slug="google-gemini",
            provider_type=ProviderType.GOOGLE_GENAI,
            secret_id=PydanticObjectId(),
            created_by="admin",
            updated_by="admin",
        )
    )

    provider_service = MagicMock()
    from app.schemas.provider import ProviderInspectResponse
    from app.services.provider_service import infer_model_capabilities

    discovered_list = [
        infer_model_capabilities("gemini-1.5-pro", "Gemini 1.5 Pro"),
        infer_model_capabilities("gemini-1.5-flash", "Gemini 1.5 Flash"),
    ]
    provider_service.live_provider_models = AsyncMock(
        return_value=ProviderInspectResponse(
            provider_type=ProviderType.GOOGLE_GENAI,
            models=discovered_list,
            total_models=2,
        )
    )

    catalog_service = ModelCatalogService(
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        provider_service=provider_service,
    )

    summary = await catalog_service.discover_models(active_project.id, prov.id, actor_id="admin")
    assert summary.discovered_count == 2
    assert summary.created_count == 2
    assert summary.updated_count == 0

    # Rediscover: should update existing rather than duplicate
    summary2 = await catalog_service.discover_models(active_project.id, prov.id, actor_id="admin")
    assert summary2.created_count == 0
    assert summary2.updated_count == 2


# ==============================================================================
# ModelRoutingService Tests (FR-07)
# ==============================================================================


@pytest.mark.asyncio
async def test_routing_policy_crud_and_failover_resolution(active_project):
    policy_repo = FakeProjectRoutingPolicyRepository()
    model_repo = FakeProjectModelRepository()
    provider_repo = FakeProjectProviderRepository()
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()
    audit_repo.log_event = AsyncMock()

    # 1. Primary provider (Degraded)
    primary_prov = await provider_repo.create(
        ProjectProvider(
            project_id=active_project.id,
            name="Primary OpenAI",
            slug="primary-openai",
            provider_type=ProviderType.OPENAI,
            secret_id=PydanticObjectId(),
            status=ProviderStatus.DEGRADED,
            created_by="admin",
            updated_by="admin",
        )
    )
    primary_model = await model_repo.create(
        ProjectModel(
            project_id=active_project.id,
            provider_id=primary_prov.id,
            model_id="gpt-4o",
            display_name="Primary GPT-4o",
        )
    )

    # 2. Backup provider (Active)
    backup_prov = await provider_repo.create(
        ProjectProvider(
            project_id=active_project.id,
            name="Backup Anthropic",
            slug="backup-anthropic",
            provider_type=ProviderType.ANTHROPIC,
            secret_id=PydanticObjectId(),
            status=ProviderStatus.ACTIVE,
            created_by="admin",
            updated_by="admin",
        )
    )
    backup_model = await model_repo.create(
        ProjectModel(
            project_id=active_project.id,
            provider_id=backup_prov.id,
            model_id="claude-3-5-sonnet",
            display_name="Backup Claude 3.5 Sonnet",
        )
    )

    routing_service = ModelRoutingService(
        routing_policy_repo=policy_repo,
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
    )

    policy = await routing_service.create_policy(
        active_project.id,
        RoutingPolicyCreateRequest(
            name="General Chat Resilient Policy",
            primary_model_id=str(primary_model.id),
            fallback_model_ids=[str(backup_model.id)],
        ),
        actor_id="admin",
    )
    assert policy.name == "General Chat Resilient Policy"

    # Resolve model: primary is DEGRADED -> automatically fall back to backup candidate
    resolved = await routing_service.resolve_model(
        active_project.id,
        ModelResolutionRequest(model_identifier="General Chat Resilient Policy"),
        actor_id="agent_worker",
    )

    assert resolved.is_fallback is True
    assert resolved.model_id == str(backup_model.id)
    assert resolved.upstream_model_id == "claude-3-5-sonnet"
    assert resolved.provider_id == str(backup_prov.id)

    # Audit fallback logged
    audit_repo.log_event.assert_called_once()
    assert audit_repo.log_event.call_args.kwargs["action"] == ProjectAuditAction.ROUTING_FALLBACK


# ==============================================================================
# FR-08 Secret Unlink Invariant Test
# ==============================================================================


@pytest.mark.asyncio
async def test_secret_unlink_invariant_prevents_deletion(active_project, sample_secret, mock_crypto):
    provider_repo = FakeProjectProviderRepository()
    secret_repo = MagicMock()
    secret_repo.get_by_id_and_project = AsyncMock(return_value=sample_secret)
    secret_repo.soft_delete = AsyncMock(return_value=True)
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    secret_service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
        provider_repo=provider_repo,
    )

    # Register an active provider referencing sample_secret.id
    prov = await provider_repo.create(
        ProjectProvider(
            project_id=active_project.id,
            name="Dependent Provider",
            slug="dependent-prov",
            provider_type=ProviderType.OPENAI,
            secret_id=sample_secret.id,
            created_by="admin",
            updated_by="admin",
        )
    )

    # Attempting to delete secret must be rejected with SecretInUseError
    with pytest.raises(SecretInUseError) as exc_info:
        await secret_service.delete_secret(active_project.id, sample_secret.id, actor_id="admin")
    assert exc_info.value.code == "SECRET_IN_USE"

    # Soft-delete provider first -> secret unlink invariant satisfied -> delete succeeds
    await provider_repo.soft_delete(prov.id, active_project.id)
    success = await secret_service.delete_secret(active_project.id, sample_secret.id, actor_id="admin")
    assert success is True


# ==============================================================================
# FR-10 Cascading Purge Test in ProjectService
# ==============================================================================


@pytest.mark.asyncio
async def test_cascading_purge_invokes_provider_and_model_repos(active_project):
    project_repo = MagicMock()
    project_repo.get_by_id_or_slug = AsyncMock(return_value=active_project)
    project_repo.transition_status = AsyncMock()

    member_repo = MagicMock()
    member_repo.get_membership = AsyncMock(return_value=MagicMock(role=ProjectRole.OWNER))
    member_repo.delete_by_project_id = AsyncMock(return_value=1)

    audit_repo = MagicMock()
    audit_repo.log_event = AsyncMock()

    model_repo = MagicMock()
    model_repo.purge_by_project = AsyncMock(return_value=5)

    provider_repo = MagicMock()
    provider_repo.purge_by_project = AsyncMock(return_value=2)

    routing_repo = MagicMock()
    routing_repo.purge_by_project = AsyncMock(return_value=1)

    project_service = ProjectService(
        project_repo=project_repo,
        member_repo=member_repo,
        audit_repo=audit_repo,
        model_repo=model_repo,
        provider_repo=provider_repo,
        routing_policy_repo=routing_repo,
    )

    # Set project status to SOFT_DELETED so purge is legal
    active_project.status = ProjectStatus.SOFT_DELETED

    res = await project_service.purge_project(active_project.id, user_id="user_owner")
    assert res["purged"] is True

    # Verify purge_by_project invoked on all three repos
    model_repo.purge_by_project.assert_called_once_with(active_project.id)
    provider_repo.purge_by_project.assert_called_once_with(active_project.id)
    routing_repo.purge_by_project.assert_called_once_with(active_project.id)

    # Verify MODEL_PURGED and PROVIDER_PURGED audit logs emitted
    actions_logged = [c.kwargs["action"] for c in audit_repo.log_event.call_args_list]
    assert ProjectAuditAction.MODEL_PURGED in actions_logged
    assert ProjectAuditAction.PROVIDER_PURGED in actions_logged
