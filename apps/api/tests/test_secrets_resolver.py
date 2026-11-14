from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
import pytest
from beanie import init_beanie

from app.core.crypto import CryptoService, EncryptedEnvelope
from app.core.exceptions import (
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.models.project import Project, ProjectAuditAction, ProjectStatus
from app.models.secret import ProjectSecret
from app.repositories.project_audit_repository import ProjectAuditRepository
from app.repositories.project_repository import ProjectRepository
from app.repositories.secret_repository import ProjectSecretRepository
from app.schemas.secret import SecretBatchResolveResponse
from app.services.runtime_secret_resolver import RuntimeSecretResolver


@pytest.fixture(autouse=True)
async def init_mock_beanie():
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])

    col = MagicMock()
    col.name = "mock_col"
    col.create_index = AsyncMock()
    col.create_indexes = AsyncMock(return_value=[])
    col.index_information = AsyncMock(return_value={})
    col.find_one = AsyncMock(return_value=None)
    col.count_documents = AsyncMock(return_value=0)
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
    db.__getitem__.return_value = col

    await init_beanie(database=db, document_models=[Project, ProjectSecret])
    return db


@pytest.fixture
def mock_crypto():
    service = MagicMock(spec=CryptoService)
    # Mapping for decryption
    secrets_map = {
        "OPENAI_API_KEY": "sk-openai-live-key",
        "PINECONE_API_KEY": "pc-test-key-999",
        "DATABASE_URL": "postgresql://usr:pwd@localhost/db",
    }

    def fake_decrypt(envelope, project_id, environment, name):
        return secrets_map.get(name, f"decrypted_{name}")

    service.decrypt_secret.side_effect = fake_decrypt
    return service


@pytest.fixture
def mock_repos():
    secret_repo = MagicMock(spec=ProjectSecretRepository)
    project_repo = MagicMock(spec=ProjectRepository)
    audit_repo = MagicMock(spec=ProjectAuditRepository)

    secret_repo.find_by_names = AsyncMock()
    project_repo.get_by_id_or_slug = AsyncMock()
    audit_repo.log_event = AsyncMock()

    return secret_repo, project_repo, audit_repo


@pytest.fixture
def active_project():
    proj = MagicMock(spec=Project)
    proj.id = ObjectId("6735e0e0e0e0e0e0e0e0e001")
    proj.status = ProjectStatus.ACTIVE
    proj.name = "Active Project"
    return proj


def make_secret(project_id, name, environment="production", expires_at=None):
    return ProjectSecret(
        id=ObjectId(),
        project_id=project_id,
        name=name,
        environment=environment,
        envelope=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
            ciphertext=f"Y2lwaGVy_{name}",
            nonce="MTIzNDU2Nzg5MDEy",
            auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            kek_id="local-v1",
        ),
        revision=1,
        expires_at=expires_at,
        is_deleted=False,
        created_by="user_admin",
        updated_by="user_admin",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_resolve_secrets_happy_path(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project

    sec1 = make_secret(active_project.id, "OPENAI_API_KEY")
    sec2 = make_secret(active_project.id, "PINECONE_API_KEY")

    secret_repo.find_by_names.return_value = [sec1, sec2]

    resolver = RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    result = await resolver.resolve_secrets(
        project_id=active_project.id,
        names=["OPENAI_API_KEY", "PINECONE_API_KEY"],
        environment="production",
        execution_id="exec_12345",
        actor_id="worker_agent_01",
    )

    assert isinstance(result, SecretBatchResolveResponse)
    assert result.resolved == {
        "OPENAI_API_KEY": "sk-openai-live-key",
        "PINECONE_API_KEY": "pc-test-key-999",
    }
    assert result.missing == []

    # Verify audit event emitted (names only, ZERO PLAINTEXT)
    audit_repo.log_event.assert_called_once()
    call = audit_repo.log_event.call_args[1]
    assert call["action"] == ProjectAuditAction.SECRET_ACCESSED
    assert call["actor_id"] == "worker_agent_01"
    assert call["payload"]["execution_id"] == "exec_12345"
    assert sorted(call["payload"]["resolved_keys"]) == ["OPENAI_API_KEY", "PINECONE_API_KEY"]
    assert call["payload"]["missing_keys"] == []


@pytest.mark.asyncio
async def test_resolve_secrets_missing_keys(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project

    sec1 = make_secret(active_project.id, "OPENAI_API_KEY")
    secret_repo.find_by_names.return_value = [sec1]

    resolver = RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    result = await resolver.resolve_secrets(
        project_id=active_project.id,
        names=["OPENAI_API_KEY", "UNKNOWN_KEY", "MISSING_KEY"],
        environment="production",
    )

    assert result.resolved == {"OPENAI_API_KEY": "sk-openai-live-key"}
    assert set(result.missing) == {"UNKNOWN_KEY", "MISSING_KEY"}

    audit_repo.log_event.assert_called_once()
    call = audit_repo.log_event.call_args[1]
    assert set(call["payload"]["missing_keys"]) == {"UNKNOWN_KEY", "MISSING_KEY"}


@pytest.mark.asyncio
async def test_resolve_secrets_expiration_filtering(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project

    now = datetime.now(timezone.utc)
    expired_secret = make_secret(
        active_project.id,
        "DATABASE_URL",
        expires_at=now - timedelta(hours=1),
    )
    valid_secret = make_secret(
        active_project.id,
        "OPENAI_API_KEY",
        expires_at=now + timedelta(days=30),
    )

    secret_repo.find_by_names.return_value = [expired_secret, valid_secret]

    resolver = RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    result = await resolver.resolve_secrets(
        project_id=active_project.id,
        names=["DATABASE_URL", "OPENAI_API_KEY"],
        environment="production",
    )

    # Expired secret must be excluded from resolved and marked missing
    assert "DATABASE_URL" not in result.resolved
    assert "DATABASE_URL" in result.missing
    assert result.resolved["OPENAI_API_KEY"] == "sk-openai-live-key"


@pytest.mark.asyncio
async def test_resolve_secrets_project_lifecycle_guards(mock_repos, mock_crypto):
    secret_repo, project_repo, audit_repo = mock_repos

    # Project not found
    project_repo.get_by_id_or_slug.return_value = None
    resolver = RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )
    with pytest.raises(NotFoundError):
        await resolver.resolve_secrets("unknown_id", ["KEY"])

    # Project ARCHIVED
    archived_project = MagicMock(spec=Project)
    archived_project.id = ObjectId()
    archived_project.status = ProjectStatus.ARCHIVED
    project_repo.get_by_id_or_slug.return_value = archived_project

    with pytest.raises(ProjectArchivedError):
        await resolver.resolve_secrets(archived_project.id, ["KEY"])

    # Project SOFT_DELETED
    deleted_project = MagicMock(spec=Project)
    deleted_project.id = ObjectId()
    deleted_project.status = ProjectStatus.SOFT_DELETED
    project_repo.get_by_id_or_slug.return_value = deleted_project

    with pytest.raises(ProjectDeletedError):
        await resolver.resolve_secrets(deleted_project.id, ["KEY"])

    # Project PURGED
    purged_project = MagicMock(spec=Project)
    purged_project.id = ObjectId()
    purged_project.status = ProjectStatus.PURGED
    project_repo.get_by_id_or_slug.return_value = purged_project

    with pytest.raises(ProjectPurgedError):
        await resolver.resolve_secrets(purged_project.id, ["KEY"])


def test_extract_template_placeholders():
    resolver = RuntimeSecretResolver

    template = (
        "Model: gpt-4, Key: {{secrets.OPENAI_API_KEY}}, DB: {{ secrets.DATABASE_URL }}, "
        "Pinecone: {{  secrets.PINECONE_API_KEY   }}, Duplicate: {{secrets.OPENAI_API_KEY}}"
    )

    extracted = resolver.extract_template_placeholders(template)
    assert extracted == ["DATABASE_URL", "OPENAI_API_KEY", "PINECONE_API_KEY"]

    # Template with no placeholders
    assert resolver.extract_template_placeholders("Just a normal string without variables") == []
    # Invalid variable pattern (lowercase or punctuation)
    assert resolver.extract_template_placeholders("Invalid: {{secrets.invalid-name}}") == []


def test_interpolate_templates():
    resolver = RuntimeSecretResolver

    template = (
        "Bearer {{secrets.OPENAI_API_KEY}} / {{ secrets.PINECONE_API_KEY }} / "
        "DB={{secrets.DATABASE_URL}} / Missing={{secrets.MISSING_KEY}}"
    )
    secrets_map = {
        "OPENAI_API_KEY": "sk-12345",
        "PINECONE_API_KEY": "pc-67890",
        "DATABASE_URL": "postgres://localhost:5432/db",
    }

    interpolated = resolver.interpolate_templates(template, secrets_map)

    assert "Bearer sk-12345" in interpolated
    assert "/ pc-67890 /" in interpolated
    assert "DB=postgres://localhost:5432/db" in interpolated
    # Unresolved key remains untouched
    assert "Missing={{secrets.MISSING_KEY}}" in interpolated


@pytest.mark.asyncio
async def test_resolve_and_interpolate_e2e(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project

    sec1 = make_secret(active_project.id, "OPENAI_API_KEY")
    secret_repo.find_by_names.return_value = [sec1]

    resolver = RuntimeSecretResolver(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    template = "OpenAI key is: {{ secrets.OPENAI_API_KEY }}"
    result = await resolver.resolve_and_interpolate(
        project_id=active_project.id,
        template_str=template,
        environment="production",
    )

    assert result == "OpenAI key is: sk-openai-live-key"

    # If no placeholders, returns immediately without repo queries
    secret_repo.find_by_names.reset_mock()
    no_var_template = "Static text only"
    static_res = await resolver.resolve_and_interpolate(
        project_id=active_project.id,
        template_str=no_var_template,
    )
    assert static_res == "Static text only"
    secret_repo.find_by_names.assert_not_called()
