"""
Comprehensive unit tests for Module 06 (Provider & Model Management):
- Models: ProjectProvider, ProjectModel, ProjectRoutingPolicy
- Schemas: Provider, ModelCatalog, RoutingPolicy
- Repositories: ProjectProviderRepository, ProjectModelRepository, ProjectRoutingPolicyRepository
- In-memory Fake Repositories: FakeProjectProviderRepository, FakeProjectModelRepository, FakeProjectRoutingPolicyRepository
"""
from unittest.mock import AsyncMock, MagicMock
import pytest
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.core.exceptions import (
    DuplicateModelError,
    DuplicateProviderNameError,
    DuplicateProviderSlugError,
    ModelRevisionConflictError,
    ProviderRevisionConflictError,
)
from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.models.project_model import (
    ModelType,
    ProjectModel,
)
from app.models.project_routing_policy import (
    ProjectRoutingPolicy,
)
from app.repositories import (
    ProjectModelRepository,
    ProjectProviderRepository,
    ProjectRoutingPolicyRepository,
    get_project_model_repository,
    get_project_provider_repository,
    get_project_routing_policy_repository,
)
from app.repositories.project_provider_repository import translate_provider_duplicate_key
from app.repositories.project_model_repository import translate_model_duplicate_key
from app.schemas.provider import (
    ProviderCreateRequest,
    ProviderInspectRequest,
)
from app.schemas.model_catalog import (
    ModelCreateRequest,
)
from app.schemas.routing_policy import (
    RoutingPolicyCreateRequest,
)
from tests.fakes.fake_project_provider_repository import FakeProjectProviderRepository
from tests.fakes.fake_project_model_repository import FakeProjectModelRepository
from tests.fakes.fake_project_routing_policy_repository import FakeProjectRoutingPolicyRepository


@pytest.fixture
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
        document_models=[ProjectProvider, ProjectModel, ProjectRoutingPolicy],
    )
    return db


# ==============================================================================
# Model Invariant & Schema Validation Tests
# ==============================================================================


def test_model_invariants_settings():
    """Ensure is_root is NOT True and collection names match specification."""
    # Invariant 1: Never set is_root = True on BaseDocument
    assert getattr(ProjectProvider.get_settings(), "is_root", False) is False
    assert getattr(ProjectModel.get_settings(), "is_root", False) is False
    assert getattr(ProjectRoutingPolicy.get_settings(), "is_root", False) is False

    assert ProjectProvider.get_settings().name == "project_providers"
    assert ProjectModel.get_settings().name == "project_models"
    assert ProjectRoutingPolicy.get_settings().name == "project_routing_policies"


def test_provider_schema_validations():
    """Test ProviderCreateRequest validations: CRLF injection & custom provider base_url."""
    secret_id = str(ObjectId())

    # Valid custom provider
    req = ProviderCreateRequest(
        name="DeepSeek Custom",
        slug="deepseek-custom",
        provider_type=ProviderType.CUSTOM_OPENAI_COMPATIBLE,
        secret_id=secret_id,
        base_url="https://api.deepseek.com/v1",
        custom_headers={"X-Custom": "Valid"},
    )
    assert req.name == "DeepSeek Custom"
    assert req.base_url == "https://api.deepseek.com/v1"

    # Custom provider missing base_url -> raises ValidationError
    with pytest.raises(ValueError, match="base_url is required"):
        ProviderCreateRequest(
            name="DeepSeek Custom",
            provider_type=ProviderType.CUSTOM_OPENAI_COMPATIBLE,
            secret_id=secret_id,
        )

    # CRLF injection in headers -> raises ValueError
    with pytest.raises(ValueError, match="CRLF injection detected"):
        ProviderCreateRequest(
            name="OpenAI Valid",
            provider_type=ProviderType.OPENAI,
            secret_id=secret_id,
            custom_headers={"Injected\r\nHeader": "bad"},
        )


def test_provider_inspect_schema_validation():
    """Test ProviderInspectRequest requires either api_key or secret_id."""
    with pytest.raises(ValueError, match="Either secret_id or api_key must be provided"):
        ProviderInspectRequest(provider_type=ProviderType.OPENAI)

    # Valid with secret_id
    req = ProviderInspectRequest(provider_type=ProviderType.OPENAI, secret_id=str(ObjectId()))
    assert req.secret_id is not None


def test_model_schema_validations():
    """Test ModelCreateRequest and ModelUpdateRequest validation."""
    prov_id = str(ObjectId())
    req = ModelCreateRequest(
        provider_id=prov_id,
        model_id="gpt-4o",
        display_name="GPT-4o Omnimodel",
        supports_tools=True,
        supports_vision=True,
    )
    assert req.model_id == "gpt-4o"
    assert req.supports_tools is True
    assert req.supports_vision is True

    # Temperature out of bounds
    with pytest.raises(ValueError):
        ModelCreateRequest(
            provider_id=prov_id,
            model_id="gpt-4o",
            display_name="GPT-4o",
            default_temperature=3.5,
        )


def test_routing_policy_schema_validation():
    """Test RoutingPolicyCreateRequest validation."""
    pri_id = str(ObjectId())
    fb_ids = [str(ObjectId()) for _ in range(3)]
    req = RoutingPolicyCreateRequest(
        name="Reasoning Policy",
        primary_model_id=pri_id,
        fallback_model_ids=fb_ids,
    )
    assert len(req.fallback_model_ids) == 3

    # Fallback model IDs exceeding max limit of 5
    with pytest.raises(ValueError):
        RoutingPolicyCreateRequest(
            name="Policy",
            primary_model_id=pri_id,
            fallback_model_ids=[str(ObjectId()) for _ in range(6)],
        )


# ==============================================================================
# In-Memory Fake Provider Repository Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_fake_provider_repo_crud_and_uniqueness():
    repo = FakeProjectProviderRepository()
    project_id = PydanticObjectId()
    secret_id = PydanticObjectId()

    provider1 = ProjectProvider(
        project_id=project_id,
        name="Main OpenAI",
        slug="main-openai",
        provider_type=ProviderType.OPENAI,
        secret_id=secret_id,
        created_by="user_123",
        updated_by="user_123",
    )
    created1 = await repo.create(provider1)
    assert created1.id is not None
    assert created1.revision == 1

    # Unique slug collision
    provider_dup_slug = ProjectProvider(
        project_id=project_id,
        name="Another OpenAI",
        slug="main-openai",
        provider_type=ProviderType.OPENAI,
        secret_id=secret_id,
        created_by="user_123",
        updated_by="user_123",
    )
    with pytest.raises(DuplicateProviderSlugError):
        await repo.create(provider_dup_slug)

    # Unique name collision
    provider_dup_name = ProjectProvider(
        project_id=project_id,
        name="Main OpenAI",
        slug="different-slug",
        provider_type=ProviderType.OPENAI,
        secret_id=secret_id,
        created_by="user_123",
        updated_by="user_123",
    )
    with pytest.raises(DuplicateProviderNameError):
        await repo.create(provider_dup_name)

    # Different project can reuse slug/name
    diff_project_id = PydanticObjectId()
    provider_diff_proj = ProjectProvider(
        project_id=diff_project_id,
        name="Main OpenAI",
        slug="main-openai",
        provider_type=ProviderType.OPENAI,
        secret_id=secret_id,
        created_by="user_123",
        updated_by="user_123",
    )
    created_diff = await repo.create(provider_diff_proj)
    assert created_diff.id is not None

    # Count by secret_id
    count = await repo.count_by_secret_id(secret_id)
    assert count == 2


@pytest.mark.asyncio
async def test_fake_provider_repo_occ_and_healthcheck():
    repo = FakeProjectProviderRepository()
    project_id = PydanticObjectId()
    secret_id = PydanticObjectId()

    provider = await repo.create(
        ProjectProvider(
            project_id=project_id,
            name="Anthropic Prod",
            slug="anthropic-prod",
            provider_type=ProviderType.ANTHROPIC,
            secret_id=secret_id,
            is_default=True,
            created_by="user_1",
            updated_by="user_1",
        )
    )

    # OCC Update success
    updated = await repo.update_with_revision(
        provider_id=provider.id,
        project_id=project_id,
        expected_revision=1,
        update_dict={"timeout_seconds": 90},
    )
    assert updated.revision == 2
    assert updated.timeout_seconds == 90

    # OCC Update mismatch
    with pytest.raises(ProviderRevisionConflictError):
        await repo.update_with_revision(
            provider_id=provider.id,
            project_id=project_id,
            expected_revision=1,  # Stale revision
            update_dict={"timeout_seconds": 120},
        )

    # Healthcheck update
    checked = await repo.update_healthcheck(
        provider_id=provider.id,
        project_id=project_id,
        healthcheck_status=HealthcheckStatus.HEALTHY,
        latency_ms=150,
        message="Endpoint reachable",
        status=ProviderStatus.ACTIVE,
    )
    assert checked is not None
    assert checked.healthcheck_status == HealthcheckStatus.HEALTHY
    assert checked.healthcheck_latency_ms == 150

    # Default provider clearing
    provider2 = await repo.create(
        ProjectProvider(
            project_id=project_id,
            name="Google GenAI",
            slug="google-genai",
            provider_type=ProviderType.GOOGLE_GENAI,
            secret_id=secret_id,
            is_default=True,
            created_by="user_1",
            updated_by="user_1",
        )
    )
    unset_count = await repo.unset_other_defaults(project_id, exclude_id=provider2.id)
    assert unset_count == 1
    reloaded_prov1 = await repo.get_by_id_and_project(provider.id, project_id)
    assert reloaded_prov1.is_default is False

    # Soft delete
    deleted = await repo.soft_delete(provider.id, project_id)
    assert deleted is True
    assert await repo.get_by_id_and_project(provider.id, project_id) is None
    assert await repo.get_by_id_and_project(provider.id, project_id, include_deleted=True) is not None

    # Purge by project
    purged = await repo.purge_by_project(project_id)
    assert purged == 2


# ==============================================================================
# In-Memory Fake Model Repository Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_fake_model_repo_crud_and_capabilities():
    repo = FakeProjectModelRepository()
    project_id = PydanticObjectId()
    provider_id = PydanticObjectId()

    model1 = ProjectModel(
        project_id=project_id,
        provider_id=provider_id,
        model_id="gemini-2.0-flash",
        display_name="Gemini 2.0 Flash",
        model_type=ModelType.CHAT_COMPLETION,
        supports_tools=True,
        supports_vision=True,
        supports_streaming=True,
        is_default=True,
    )
    created1 = await repo.create(model1)
    assert created1.id is not None
    assert created1.revision == 1

    # Unique model_id per provider
    model_dup = ProjectModel(
        project_id=project_id,
        provider_id=provider_id,
        model_id="gemini-2.0-flash",
        display_name="Gemini 2.0 Flash Copy",
    )
    with pytest.raises(DuplicateModelError):
        await repo.create(model_dup)

    # Capability filtering
    items, total = await repo.list_by_project(
        project_id=project_id,
        supports_tools=True,
        supports_vision=True,
    )
    assert total == 1
    assert items[0].model_id == "gemini-2.0-flash"

    # OCC update
    updated = await repo.update_with_revision(
        model_id=created1.id,
        project_id=project_id,
        expected_revision=1,
        update_dict={"display_name": "Gemini 2.0 Flash Experimental"},
    )
    assert updated.revision == 2
    assert updated.display_name == "Gemini 2.0 Flash Experimental"

    with pytest.raises(ModelRevisionConflictError):
        await repo.update_with_revision(
            model_id=created1.id,
            project_id=project_id,
            expected_revision=1,
            update_dict={"display_name": "Stale"},
        )

    # Cascading soft delete by provider
    cascaded = await repo.soft_delete_by_provider(provider_id, project_id)
    assert cascaded == 1
    assert await repo.get_by_id_and_project(created1.id, project_id) is None


# ==============================================================================
# In-Memory Fake Routing Policy Repository Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_fake_routing_policy_repo_crud():
    repo = FakeProjectRoutingPolicyRepository()
    project_id = PydanticObjectId()
    primary_id = PydanticObjectId()
    fallback_id = PydanticObjectId()

    policy = await repo.create(
        ProjectRoutingPolicy(
            project_id=project_id,
            name="Primary with Failover",
            primary_model_id=primary_id,
            fallback_model_ids=[fallback_id],
        )
    )
    assert policy.id is not None
    assert policy.revision == 1

    # Get by name
    found = await repo.get_by_name(project_id, "Primary with Failover")
    assert found is not None
    assert found.primary_model_id == primary_id

    # OCC Update
    updated = await repo.update_with_revision(
        policy_id=policy.id,
        project_id=project_id,
        expected_revision=1,
        update_dict={"retry_timeout_ms": 5000},
    )
    assert updated.revision == 2
    assert updated.retry_timeout_ms == 5000

    # Purge by project
    purged = await repo.purge_by_project(project_id)
    assert purged == 1


# ==============================================================================
# Duplicate Key Translation & Factory Tests
# ==============================================================================


def test_duplicate_key_error_translation():
    proj = ProjectProvider(
        project_id=PydanticObjectId(),
        name="Provider Name",
        slug="provider-slug",
        provider_type=ProviderType.OPENAI,
        secret_id=PydanticObjectId(),
        created_by="user_1",
        updated_by="user_1",
    )

    slug_exc = DuplicateKeyError("E11000 duplicate key error", details={"keyPattern": {"project_id": 1, "slug": 1}})
    res = translate_provider_duplicate_key(slug_exc, proj)
    assert isinstance(res, DuplicateProviderSlugError)

    name_exc = DuplicateKeyError("E11000 duplicate key error", details={"keyPattern": {"project_id": 1, "name": 1}})
    res_name = translate_provider_duplicate_key(name_exc, proj)
    assert isinstance(res_name, DuplicateProviderNameError)

    model = ProjectModel(
        project_id=PydanticObjectId(),
        provider_id=PydanticObjectId(),
        model_id="gpt-4o",
        display_name="GPT-4o",
    )
    model_exc = DuplicateKeyError("E11000", details={"keyPattern": {"provider_id": 1, "model_id": 1}})
    res_model = translate_model_duplicate_key(model_exc, model)
    assert isinstance(res_model, DuplicateModelError)


def test_di_factory_providers():
    prov_repo = get_project_provider_repository()
    assert isinstance(prov_repo, ProjectProviderRepository)

    mod_repo = get_project_model_repository()
    assert isinstance(mod_repo, ProjectModelRepository)

    route_repo = get_project_routing_policy_repository()
    assert isinstance(route_repo, ProjectRoutingPolicyRepository)
