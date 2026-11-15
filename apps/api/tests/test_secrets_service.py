from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
import pytest
from pydantic import SecretStr

from app.core.crypto import CryptoService, EncryptedEnvelope
from app.core.exceptions import (
    ConflictError,
    CryptographicIntegrityError,
    ProjectArchivedError,
)
from app.models.project import Project, ProjectAuditAction, ProjectStatus
from app.models.secret import ProjectSecret
from beanie import init_beanie
from app.repositories.project_audit_repository import ProjectAuditRepository
from app.repositories.project_repository import ProjectRepository
from app.repositories.secret_repository import ProjectSecretRepository
from app.schemas.secret import (
    SecretCreateRequest,
    SecretResponse,
    SecretRotateRequest,
    SecretSummaryResponse,
    SecretUpdateRequest,
    SecretValueResponse,
)
from app.services.secret_service import ProjectSecretService


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
    # Default behavior for encrypt_secret
    service.encrypt_secret.return_value = EncryptedEnvelope(
        algorithm="AES-256-GCM",
        encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
        ciphertext="Y2lwaGVydGV4dF9ieXRlcw==",
        nonce="MTIzNDU2Nzg5MDEy",
        auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
        kek_id="local-v1",
    )
    service.decrypt_secret.return_value = "decrypted_secret_value_123"
    return service


@pytest.fixture
def mock_repos():
    secret_repo = MagicMock(spec=ProjectSecretRepository)
    project_repo = MagicMock(spec=ProjectRepository)
    audit_repo = MagicMock(spec=ProjectAuditRepository)

    # Async methods
    secret_repo.check_exists = AsyncMock(return_value=False)
    secret_repo.create = AsyncMock()
    secret_repo.get_by_id_and_project = AsyncMock()
    secret_repo.list_by_project = AsyncMock()
    secret_repo.update_with_revision = AsyncMock()
    secret_repo.soft_delete = AsyncMock(return_value=True)
    secret_repo.purge = AsyncMock(return_value=True)
    secret_repo.find_by_names = AsyncMock()

    project_repo.get_by_id_or_slug = AsyncMock()

    audit_repo.log_event = AsyncMock()

    return secret_repo, project_repo, audit_repo


@pytest.fixture
def active_project():
    proj = MagicMock(spec=Project)
    proj.id = ObjectId("6735e0e0e0e0e0e0e0e0e001")
    proj.status = ProjectStatus.ACTIVE
    proj.name = "Test Project"
    return proj


@pytest.fixture
def archived_project():
    proj = MagicMock(spec=Project)
    proj.id = ObjectId("6735e0e0e0e0e0e0e0e0e002")
    proj.status = ProjectStatus.ARCHIVED
    proj.name = "Archived Project"
    return proj


@pytest.fixture
def sample_secret(active_project):
    return ProjectSecret(
        id=ObjectId("6735e0e0e0e0e0e0e0e0e010"),
        project_id=active_project.id,
        name="OPENAI_API_KEY",
        environment="production",
        description="OpenAI Key for GPT-4",
        tags=["ai", "prod"],
        is_system=False,
        envelope=EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek="d3JhcHBlZF9kZWtfYnl0ZXM=",
            ciphertext="Y2lwaGVydGV4dF9ieXRlcw==",
            nonce="MTIzNDU2Nzg5MDEy",
            auth_tag="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            kek_id="local-v1",
        ),
        revision=1,
        last_rotated_at=None,
        expires_at=None,
        is_deleted=False,
        deleted_at=None,
        created_by="user_admin",
        updated_by="user_admin",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_create_secret_happy_path(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.check_exists.return_value = False

    def fake_create(sec):
        sec.id = ObjectId("6735e0e0e0e0e0e0e0e0e099")
        sec.created_at = datetime.now(timezone.utc)
        sec.updated_at = datetime.now(timezone.utc)
        return sec

    secret_repo.create.side_effect = fake_create

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretCreateRequest(
        name="ANTHROPIC_API_KEY",
        value=SecretStr("sk-ant-test-key-12345"),
        environment="production",
        description="Anthropic Claude API key",
        tags=["llm", "claude"],
    )

    result = await service.create_secret(active_project.id, req, actor_id="user_creator")

    assert isinstance(result, SecretResponse)
    assert result.name == "ANTHROPIC_API_KEY"
    assert result.environment == "production"
    assert result.revision == 1
    assert result.created_by == "user_creator"
    assert not hasattr(result, "value")

    # Verify CryptoService was called with canonical AAD components
    mock_crypto.encrypt_secret.assert_called_once_with(
        "sk-ant-test-key-12345",
        str(active_project.id),
        "production",
        "ANTHROPIC_API_KEY",
    )

    # Verify audit event emitted
    audit_repo.log_event.assert_called_once()
    call_args = audit_repo.log_event.call_args[1]
    assert call_args["action"] == ProjectAuditAction.SECRET_CREATED
    assert call_args["actor_id"] == "user_creator"
    assert call_args["payload"]["name"] == "ANTHROPIC_API_KEY"
    assert call_args["payload"]["revision"] == 1


@pytest.mark.asyncio
async def test_create_secret_duplicate_conflict(mock_repos, mock_crypto, active_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.check_exists.return_value = True

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretCreateRequest(
        name="OPENAI_API_KEY",
        value=SecretStr("duplicate-key"),
        environment="production",
    )

    with pytest.raises(ConflictError) as exc_info:
        await service.create_secret(active_project.id, req, actor_id="user_creator")

    assert "already exists in environment 'production'" in str(exc_info.value)
    mock_crypto.encrypt_secret.assert_not_called()
    audit_repo.log_event.assert_not_called()


@pytest.mark.asyncio
async def test_create_secret_archived_freeze(mock_repos, mock_crypto, archived_project):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = archived_project

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretCreateRequest(
        name="NEW_KEY",
        value=SecretStr("some-secret"),
        environment="production",
    )

    with pytest.raises(ProjectArchivedError):
        await service.create_secret(archived_project.id, req, actor_id="user_creator")

    secret_repo.create.assert_not_called()


@pytest.mark.asyncio
async def test_list_secrets(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.list_by_project.return_value = ([sample_secret], 1)

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    summaries, total = await service.list_secrets(
        project_id=active_project.id,
        environment="production",
        search="OPENAI",
        tags=["ai"],
        skip=0,
        limit=20,
    )

    assert total == 1
    assert len(summaries) == 1
    item = summaries[0]
    assert isinstance(item, SecretSummaryResponse)
    assert item.name == "OPENAI_API_KEY"
    assert item.revision == 1
    # Verify zero plaintext
    assert not hasattr(item, "value")
    assert not hasattr(item, "ciphertext")


@pytest.mark.asyncio
async def test_list_secrets_allowed_on_archived(mock_repos, mock_crypto, archived_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = archived_project
    secret_repo.list_by_project.return_value = ([sample_secret], 1)

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    summaries, total = await service.list_secrets(project_id=archived_project.id)
    assert total == 1
    assert len(summaries) == 1


@pytest.mark.asyncio
async def test_get_secret_metadata(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    res = await service.get_secret_metadata(active_project.id, sample_secret.id)
    assert isinstance(res, SecretResponse)
    assert res.name == "OPENAI_API_KEY"
    assert res.algorithm == "AES-256-GCM"
    assert res.kek_id == "local-v1"
    assert not hasattr(res, "value")


@pytest.mark.asyncio
async def test_update_secret_in_place_with_new_value(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    new_envelope = EncryptedEnvelope(
        algorithm="AES-256-GCM",
        encrypted_dek="bmV3X3dyYXBwZWRfZGVr",
        ciphertext="bmV3X2NpcGhlcnRleHQ=",
        nonce="bmV3X25vbmNlMTI=",
        auth_tag="bmV3X2F1dGhfdGFnMTY=",
        kek_id="local-v1",
    )
    mock_crypto.encrypt_secret.return_value = new_envelope

    def fake_update(secret_id, project_id, expected_revision, update_dict):
        assert expected_revision == 1
        assert "envelope" in update_dict
        assert update_dict["envelope"] == new_envelope
        assert update_dict["last_rotated_at"] is not None
        sample_secret.envelope = update_dict["envelope"]
        sample_secret.last_rotated_at = update_dict["last_rotated_at"]
        sample_secret.revision = 2
        sample_secret.updated_by = update_dict["updated_by"]
        return sample_secret

    secret_repo.update_with_revision.side_effect = fake_update

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretUpdateRequest(
        value=SecretStr("brand_new_openai_key"),
        description="Updated OpenAI key",
        revision=1,
    )

    res = await service.update_secret(active_project.id, sample_secret.id, req, actor_id="user_updater")

    assert res.revision == 2
    assert res.last_rotated_at is not None

    # Verify audit event
    audit_repo.log_event.assert_called_once()
    payload = audit_repo.log_event.call_args[1]["payload"]
    assert payload["revision"] == 2
    assert payload["value_replaced"] is True


@pytest.mark.asyncio
async def test_update_secret_occ_conflict(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    # Simulate OCC conflict
    secret_repo.update_with_revision.side_effect = ConflictError("Secret has been modified by another process")

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretUpdateRequest(
        description="Changed description",
        revision=999,  # Stale revision
    )

    with pytest.raises(ConflictError):
        await service.update_secret(active_project.id, sample_secret.id, req, actor_id="user_updater")


@pytest.mark.asyncio
async def test_rotate_secret_in_place(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    new_envelope = EncryptedEnvelope(
        algorithm="AES-256-GCM",
        encrypted_dek="cm90YXRlZF9kZWs=",
        ciphertext="cm90YXRlZF9jaXBoZXI=",
        nonce="cm90YXRlZF9ub25jZQ==",
        auth_tag="cm90YXRlZF90YWcxNg==",
        kek_id="local-v1",
    )
    mock_crypto.encrypt_secret.return_value = new_envelope

    def fake_update(secret_id, project_id, expected_revision, update_dict):
        assert expected_revision == 1
        assert update_dict["envelope"] == new_envelope
        assert update_dict["last_rotated_at"] is not None
        sample_secret.envelope = new_envelope
        sample_secret.last_rotated_at = update_dict["last_rotated_at"]
        sample_secret.revision = 2
        return sample_secret

    secret_repo.update_with_revision.side_effect = fake_update

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretRotateRequest(
        new_value=SecretStr("rotated_secret_val"),
        revision=1,
    )

    res = await service.rotate_secret(active_project.id, sample_secret.id, req, actor_id="user_rotator")

    assert res.revision == 2
    assert res.last_rotated_at is not None

    audit_repo.log_event.assert_called_once()
    assert audit_repo.log_event.call_args[1]["action"] == ProjectAuditAction.SECRET_ROTATED


@pytest.mark.asyncio
async def test_rotate_secret_archived_freeze(mock_repos, mock_crypto, archived_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = archived_project

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    req = SecretRotateRequest(new_value=SecretStr("rotated_val"), revision=1)

    with pytest.raises(ProjectArchivedError):
        await service.rotate_secret(archived_project.id, sample_secret.id, req, actor_id="user_rotator")


@pytest.mark.asyncio
async def test_reveal_secret_value_happy_path(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret
    mock_crypto.decrypt_secret.return_value = "super_secret_decrypted_password"

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    res = await service.reveal_secret_value(
        project_id=active_project.id,
        secret_id=sample_secret.id,
        actor_id="admin_user",
        reason="Security audit check",
        client_ip="192.168.1.50",
        user_agent="AxionAdminClient/1.0",
    )

    assert isinstance(res, SecretValueResponse)
    assert res.value == "super_secret_decrypted_password"
    assert res.audit_logged is True
    assert res.name == "OPENAI_API_KEY"

    # Verify decrypt_secret called with canonical AAD components
    mock_crypto.decrypt_secret.assert_called_once_with(
        sample_secret.envelope,
        str(active_project.id),
        sample_secret.environment,
        sample_secret.name,
    )

    # Verify audit event
    audit_repo.log_event.assert_called_once()
    call = audit_repo.log_event.call_args[1]
    assert call["action"] == ProjectAuditAction.SECRET_REVEALED
    assert call["actor_id"] == "admin_user"
    assert call["payload"]["reason"] == "Security audit check"
    assert call["payload"]["client_ip"] == "192.168.1.50"


@pytest.mark.asyncio
async def test_reveal_secret_value_allowed_on_archived(mock_repos, mock_crypto, archived_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = archived_project
    secret_repo.get_by_id_and_project.return_value = sample_secret
    mock_crypto.decrypt_secret.return_value = "archived_decrypted_val"

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    res = await service.reveal_secret_value(
        project_id=archived_project.id,
        secret_id=sample_secret.id,
        actor_id="admin_user",
    )

    assert res.value == "archived_decrypted_val"


@pytest.mark.asyncio
async def test_reveal_secret_cryptographic_integrity_error(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    mock_crypto.decrypt_secret.side_effect = CryptographicIntegrityError("Ciphertext integrity verification failed")

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    with pytest.raises(CryptographicIntegrityError):
        await service.reveal_secret_value(active_project.id, sample_secret.id, actor_id="admin_user")


@pytest.mark.asyncio
async def test_soft_delete_and_purge_secret(mock_repos, mock_crypto, active_project, sample_secret):
    secret_repo, project_repo, audit_repo = mock_repos
    project_repo.get_by_id_or_slug.return_value = active_project
    secret_repo.get_by_id_and_project.return_value = sample_secret

    service = ProjectSecretService(
        secret_repo=secret_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        crypto_service=mock_crypto,
    )

    # Soft delete
    del_res = await service.delete_secret(active_project.id, sample_secret.id, actor_id="admin_user")
    assert del_res is True
    audit_repo.log_event.assert_called_once()
    assert audit_repo.log_event.call_args[1]["action"] == ProjectAuditAction.SECRET_DELETED

    audit_repo.log_event.reset_mock()

    # Purge
    purge_res = await service.purge_secret(active_project.id, sample_secret.id, actor_id="admin_user")
    assert purge_res is True
    audit_repo.log_event.assert_called_once()
    assert audit_repo.log_event.call_args[1]["action"] == ProjectAuditAction.SECRET_PURGED
