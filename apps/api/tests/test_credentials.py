"""
Unit, integration, and HTTP endpoint test suite for Project Credentials Management (MOD-03).
Covers CSPRNG key generation, irreversible SHA-256 hashing, strictly one-time plaintext delivery,
OCC revision conflicts, revocation, project tenant isolation, scope authorization,
cascading purge, debounced usage telemetry, and API endpoints.

Per AGENTS.md, all tests execute in-memory with mocked MongoDB and external dependencies.
"""
from datetime import datetime, timedelta, timezone
import re
from unittest.mock import AsyncMock, MagicMock
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
import pytest
from fastapi import Request, status
from fastapi.testclient import TestClient

from app.api.deps import (
    ApiKeyAuth,
    AuthenticatedContextAuth,
    get_api_key_auth,
    get_authenticated_context,
    get_credential_repository,
    get_credential_service,
    get_current_user,
    get_project_member_repository,
    get_project_repository,
    require_api_key_scopes,
)
from app.repositories.project_audit_repository import get_project_audit_repository
from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    CredentialExpiredError,
    CredentialRevisionConflictError,
    CredentialRevokedError,
    DuplicateCredentialNameError,
    ForbiddenError,
    InsufficientScopeError,
    InvalidCredentialError,
    NotFoundError,
    ProjectAccessDeniedError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
    RateLimitExceededError,
    UnauthorizedError,
)
from app.main import app
from app.models import DOCUMENT_MODELS
from app.models.credential import CredentialStatus, ProjectCredential
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectAuditLog,
    ProjectMember,
    ProjectRole,
    ProjectStatus,
)
from app.models.user import UserRole
from app.repositories.credential_repository import (
    InMemoryProjectCredentialRepository,
)
from app.schemas.auth import AuthenticatedActor, AuthenticatedUser
from app.schemas.credential import (
    CredentialCreateRequest,
    CredentialCreateResponse,
    CredentialResponse,
    CredentialRevokeRequest,
)
from app.services.credential_service import (
    ProjectCredentialService,
    generate_api_key,
)
from app.services.project_service import ProjectService


# ==============================================================================
# Pytest Fixtures & In-Memory Fakes Setup
# ==============================================================================


@pytest.fixture(autouse=True)
async def init_mock_beanie():
    """Initialize Beanie ODM with mocked MongoDB client for document model validation."""
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
    await init_beanie(database=db, document_models=DOCUMENT_MODELS)
    return db


def make_actor_user(user_id="user_admin", role=UserRole.USER):
    return AuthenticatedUser(
        id=user_id,
        clerk_id=user_id,
        email=f"{user_id}@example.com",
        first_name="Test",
        last_name="Admin",
        role=role,
        roles=[role.value],
        is_active=True,
        is_authenticated=True,
    )


class InMemoryAuditRepository:
    """In-memory fake repository for ProjectAuditLog events."""

    def __init__(self):
        self.logs: list[ProjectAuditLog] = []

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
    """In-memory fake repository for Project documents."""

    def __init__(self):
        self.projects: dict[str, Project] = {}

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


class InMemoryProjectMemberRepositoryFake:
    """In-memory fake repository for ProjectMember documents."""

    def __init__(self):
        self.members: dict[tuple[str, str], ProjectMember] = {}

    async def get_membership(self, project_id, user_id):
        return self.members.get((str(project_id), str(user_id)))

    async def delete_by_project_id(self, project_id):
        pid_str = str(project_id)
        to_del = [k for k in self.members if k[0] == pid_str]
        for k in to_del:
            del self.members[k]
        return len(to_del)


# ==============================================================================
# 1. Cryptographic Key Generation & Hashing Tests
# ==============================================================================


class TestKeyGeneration:
    """Verifies CSPRNG key generation, entropy, format, and SHA-256 hashing."""

    def test_key_prefix_and_format_live(self):
        raw_key, key_hash, masked_key = generate_api_key("production")
        assert raw_key.startswith("axion_live_")
        assert masked_key.startswith("axion_live_")
        assert "..." in masked_key
        assert re.match(r"^axion_live_[A-Za-z0-9_-]{40,64}$", raw_key)
        assert len(key_hash) == 64  # SHA-256 hex string

    def test_key_prefix_and_format_test_tiers(self):
        for env in ["test", "staging", "development"]:
            raw_key, key_hash, masked_key = generate_api_key(env)
            assert raw_key.startswith("axion_test_")
            assert masked_key.startswith("axion_test_")
            assert re.match(r"^axion_test_[A-Za-z0-9_-]{40,64}$", raw_key)
            assert len(key_hash) == 64

    def test_key_entropy_and_uniqueness(self):
        generated = {generate_api_key("production")[0] for _ in range(100)}
        assert len(generated) == 100

    def test_masked_key_hint_anatomy(self):
        raw_key, _, masked_key = generate_api_key("production")
        prefix = "axion_live_"
        secret_part = raw_key[len(prefix):]
        expected_mask = f"{prefix}{secret_part[:4]}...{secret_part[-4:]}"
        assert masked_key == expected_mask


# ==============================================================================
# 2. In-Memory Project Credential Repository Tests
# ==============================================================================


class TestInMemoryCredentialRepository:
    """Verifies InMemoryProjectCredentialRepository invariants, indexes, and OCC."""

    @pytest.mark.asyncio
    async def test_create_and_get_by_hash(self):
        repo = InMemoryProjectCredentialRepository()
        raw_key, key_hash, masked_key = generate_api_key("production")
        pid = PydanticObjectId()

        cred = ProjectCredential(
            project_id=pid,
            name="CI Pipeline",
            environment="production",
            key_prefix="axion_live_",
            masked_key=masked_key,
            key_hash=key_hash,
            scopes=["projects:read"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        created = await repo.create(cred)
        assert created.id is not None
        assert created.revision == 1

        fetched = await repo.get_by_hash(key_hash)
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.name == "CI Pipeline"

    @pytest.mark.asyncio
    async def test_duplicate_name_within_project_rejected(self):
        repo = InMemoryProjectCredentialRepository()
        pid = PydanticObjectId()

        c1 = ProjectCredential(
            project_id=pid,
            name="Deploy Key",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_1234...5678",
            key_hash="hash_1",
            scopes=["runs:write"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        await repo.create(c1)

        c2 = ProjectCredential(
            project_id=pid,
            name="Deploy Key",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_abcd...ef01",
            key_hash="hash_2",
            scopes=["runs:write"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        with pytest.raises(DuplicateCredentialNameError) as exc_info:
            await repo.create(c2)
        assert "Deploy Key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_same_name_allowed_across_different_projects(self):
        repo = InMemoryProjectCredentialRepository()
        pid1 = PydanticObjectId()
        pid2 = PydanticObjectId()

        c1 = ProjectCredential(
            project_id=pid1,
            name="Shared Name",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_1...1",
            key_hash="hash_1",
            scopes=["projects:read"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        c2 = ProjectCredential(
            project_id=pid2,
            name="Shared Name",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_2...2",
            key_hash="hash_2",
            scopes=["projects:read"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        doc1 = await repo.create(c1)
        doc2 = await repo.create(c2)
        assert doc1.id != doc2.id

    @pytest.mark.asyncio
    async def test_duplicate_name_allowed_if_first_is_deleted_or_revoked(self):
        repo = InMemoryProjectCredentialRepository()
        pid = PydanticObjectId()

        c1 = ProjectCredential(
            project_id=pid,
            name="Ephemeral Key",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_1...1",
            key_hash="hash_1",
            scopes=["projects:read"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        await repo.create(c1)
        # Soft-delete c1
        await repo.soft_delete(c1.id, pid)

        # Create c2 with identical name
        c2 = ProjectCredential(
            project_id=pid,
            name="Ephemeral Key",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_2...2",
            key_hash="hash_2",
            scopes=["projects:read"],
            created_by="user_admin",
            updated_by="user_admin",
        )
        doc2 = await repo.create(c2)
        assert doc2.name == "Ephemeral Key"

    @pytest.mark.asyncio
    async def test_update_with_revision_occ(self):
        repo = InMemoryProjectCredentialRepository()
        pid = PydanticObjectId()

        c = ProjectCredential(
            project_id=pid,
            name="OCC Test",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_1...1",
            key_hash="hash_occ",
            scopes=["projects:read"],
            revision=1,
            created_by="user_admin",
            updated_by="user_admin",
        )
        await repo.create(c)

        # Successful update matching revision 1 -> increments to 2
        updated = await repo.update_with_revision(
            credential_id=c.id,
            project_id=pid,
            expected_revision=1,
            update_dict={"description": "Updated notes"},
        )
        assert updated.revision == 2
        assert updated.description == "Updated notes"

        # Conflicting update with stale revision 1 -> raises CredentialRevisionConflictError
        with pytest.raises(CredentialRevisionConflictError):
            await repo.update_with_revision(
                credential_id=c.id,
                project_id=pid,
                expected_revision=1,
                update_dict={"description": "Conflicting update"},
            )

    @pytest.mark.asyncio
    async def test_record_usage_debouncing_and_total_uses(self):
        repo = InMemoryProjectCredentialRepository()
        pid = PydanticObjectId()

        c = ProjectCredential(
            project_id=pid,
            name="Telemetry Key",
            environment="production",
            key_prefix="axion_live_",
            masked_key="axion_live_1...1",
            key_hash="hash_tel",
            scopes=["projects:read"],
            total_uses=0,
            created_by="user_admin",
            updated_by="user_admin",
        )
        await repo.create(c)

        # 1st invocation: updates timestamp and increments counter
        res1 = await repo.record_usage_debounced(
            credential_id=c.id,
            client_ip="192.168.1.1",
            current_last_used=None,
            debounce_seconds=300,
        )
        assert res1 is True
        assert c.total_uses == 1
        assert c.last_used_at is not None
        first_last_used = c.last_used_at

        # 2nd invocation immediately after: debounced (no timestamp write), total_uses incremented
        res2 = await repo.record_usage_debounced(
            credential_id=c.id,
            client_ip="192.168.1.2",
            current_last_used=first_last_used,
            debounce_seconds=300,
        )
        assert res2 is False
        assert c.total_uses == 2
        assert c.last_used_at == first_last_used  # Unchanged due to debouncing


# ==============================================================================
# 3. Domain Service Tests (ProjectCredentialService)
# ==============================================================================


class TestCredentialService:
    """Verifies business logic, strictly one-time raw_key delivery, and audit logging."""

    @pytest.fixture
    def service_fixture(self):
        cred_repo = InMemoryProjectCredentialRepository()
        project_repo = InMemoryProjectRepositoryFake()
        audit_repo = InMemoryAuditRepository()

        active_proj = Project(
            name="Core Platform",
            slug="core-platform",
            owner_id="user_admin",
            status=ProjectStatus.ACTIVE,
            version=1,
        )
        active_proj.id = PydanticObjectId()
        project_repo.projects[str(active_proj.id)] = active_proj

        archived_proj = Project(
            name="Archived App",
            slug="archived-app",
            owner_id="user_admin",
            status=ProjectStatus.ARCHIVED,
            version=1,
        )
        archived_proj.id = PydanticObjectId()
        project_repo.projects[str(archived_proj.id)] = archived_proj

        service = ProjectCredentialService(
            credential_repo=cred_repo,
            project_repo=project_repo,
            audit_repo=audit_repo,
        )
        return {
            "service": service,
            "cred_repo": cred_repo,
            "project_repo": project_repo,
            "audit_repo": audit_repo,
            "project": active_proj,
            "archived_project": archived_proj,
        }

    @pytest.mark.asyncio
    async def test_create_credential_one_time_raw_key_delivery(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        cred_repo: InMemoryProjectCredentialRepository = service_fixture["cred_repo"]
        audit_repo: InMemoryAuditRepository = service_fixture["audit_repo"]
        project: Project = service_fixture["project"]

        req = CredentialCreateRequest(
            name="GitHub Action Runner",
            description="Automated CI runner",
            environment="production",
            scopes=["runs:write", "projects:read"],
            rate_limit_rpm=500,
        )
        resp: CredentialCreateResponse = await service.create_credential(
            project_id=project.id,
            request=req,
            actor_id="user_admin",
        )

        # 1. Plaintext raw_key strictly present in response
        assert resp.raw_key.startswith("axion_live_")
        assert resp.name == "GitHub Action Runner"
        assert resp.scopes == ["runs:write", "projects:read"]
        assert resp.revision == 1

        # 2. Database contains ONLY irreversible hash, NEVER raw_key
        db_doc = await cred_repo.get_by_id_and_project(resp.id, project.id)
        assert db_doc is not None
        assert not hasattr(db_doc, "raw_key")
        assert db_doc.key_hash != resp.raw_key
        assert len(db_doc.key_hash) == 64

        # 3. Emits CREDENTIAL_CREATED audit event
        assert len(audit_repo.logs) == 1
        assert audit_repo.logs[0].action == ProjectAuditAction.CREDENTIAL_CREATED
        assert audit_repo.logs[0].payload["credential_id"] == resp.id

    @pytest.mark.asyncio
    async def test_create_credential_validations(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        project: Project = service_fixture["project"]

        # Reject past expiration
        with pytest.raises(BadRequestError) as exc_info:
            await service.create_credential(
                project_id=project.id,
                request=CredentialCreateRequest(
                    name="Expired Key",
                    scopes=["projects:read"],
                    expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                ),
                actor_id="user_admin",
            )
        assert "future" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_mutations_blocked_on_archived_project(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        archived_proj: Project = service_fixture["archived_project"]

        with pytest.raises(ProjectArchivedError):
            await service.create_credential(
                project_id=archived_proj.id,
                request=CredentialCreateRequest(
                    name="Blocked Key",
                    scopes=["projects:read"],
                ),
                actor_id="user_admin",
            )

    @pytest.mark.asyncio
    async def test_creation_blocked_on_purged_project(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        project_repo = service_fixture["project_repo"]

        purged_proj = Project(
            name="Purged Proj",
            slug="purged-proj",
            owner_id="user_admin",
            status=ProjectStatus.PURGED,
            version=1,
        )
        purged_proj.id = PydanticObjectId()
        project_repo.projects[str(purged_proj.id)] = purged_proj

        with pytest.raises(ProjectPurgedError):
            await service.create_credential(
                project_id=purged_proj.id,
                request=CredentialCreateRequest(
                    name="Blocked Key",
                    scopes=["projects:read"],
                ),
                actor_id="user_admin",
            )

    @pytest.mark.asyncio
    async def test_list_and_get_never_reveal_raw_key(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        project: Project = service_fixture["project"]

        create_resp = await service.create_credential(
            project_id=project.id,
            request=CredentialCreateRequest(
                name="Key One",
                scopes=["projects:read"],
            ),
            actor_id="user_admin",
        )

        # GET single credential
        get_resp: CredentialResponse = await service.get_credential(project.id, create_resp.id)
        assert not hasattr(get_resp, "raw_key")
        assert get_resp.masked_key == create_resp.masked_key

        # LIST credentials
        list_resp, total = await service.list_credentials(project.id)
        assert total == 1
        assert not hasattr(list_resp[0], "raw_key")

    @pytest.mark.asyncio
    async def test_credentials_are_immutable_service_has_no_update_method(self, service_fixture):
        """Verifies requirement change: credentials CANNOT be updated (immutable once created)."""
        service: ProjectCredentialService = service_fixture["service"]
        assert not hasattr(service, "update_credential")
        assert not hasattr(service, "update")

    @pytest.mark.asyncio
    async def test_revoke_credential_lifecycle(self, service_fixture):
        service: ProjectCredentialService = service_fixture["service"]
        audit_repo: InMemoryAuditRepository = service_fixture["audit_repo"]
        project: Project = service_fixture["project"]

        create_resp = await service.create_credential(
            project_id=project.id,
            request=CredentialCreateRequest(name="Key to Revoke", scopes=["projects:read"]),
            actor_id="user_admin",
        )

        revoked = await service.revoke_credential(
            project_id=project.id,
            credential_id=create_resp.id,
            request=CredentialRevokeRequest(expected_revision=1, reason="Compromised key"),
            actor_id="user_admin",
        )
        assert revoked.status == CredentialStatus.REVOKED
        assert revoked.revision == 2

        # Revoking already revoked credential returns 409 Conflict
        with pytest.raises(ConflictError):
            await service.revoke_credential(
                project_id=project.id,
                credential_id=create_resp.id,
                request=CredentialRevokeRequest(expected_revision=2),
                actor_id="user_admin",
            )

        # Audit event recorded
        assert any(log.action == ProjectAuditAction.CREDENTIAL_REVOKED for log in audit_repo.logs)

    @pytest.mark.asyncio
    async def test_no_rotate_method_exists(self, service_fixture):
        """Verifies requirement change: credentials CANNOT be rotated."""
        service: ProjectCredentialService = service_fixture["service"]
        assert not hasattr(service, "rotate_credential")
        assert not hasattr(service, "rotate")


# ==============================================================================
# 4. Cascading Purge Integration Tests
# ==============================================================================


class TestCascadingPurge:
    """Verifies that permanent project purge cascades to delete all project credentials."""

    @pytest.mark.asyncio
    async def test_purge_project_cascades_to_credentials(self):
        project_repo = InMemoryProjectRepositoryFake()
        member_repo = InMemoryProjectMemberRepositoryFake()
        cred_repo = InMemoryProjectCredentialRepository()
        audit_repo = InMemoryAuditRepository()

        proj_id = PydanticObjectId()
        owner_id = "user_owner"

        proj = Project(
            name="Purge Target",
            slug="purge-target",
            owner_id=owner_id,
            status=ProjectStatus.SOFT_DELETED,  # Must be soft-deleted to be purged
            version=2,
        )
        proj.id = proj_id
        project_repo.projects[str(proj_id)] = proj

        member = ProjectMember(
            project_id=proj_id,
            user_id=owner_id,
            role=ProjectRole.OWNER,
        )
        member_repo.members[(str(proj_id), owner_id)] = member

        # Create 3 credentials belonging to this project
        for i in range(3):
            _, kh, mk = generate_api_key("production")
            await cred_repo.create(
                ProjectCredential(
                    project_id=proj_id,
                    name=f"Key-{i}",
                    environment="production",
                    key_prefix="axion_live_",
                    masked_key=mk,
                    key_hash=kh,
                    scopes=["projects:read"],
                    created_by=owner_id,
                    updated_by=owner_id,
                )
            )

        # Verify 3 exist
        creds_before, total = await cred_repo.list_by_project(proj_id)
        assert total == 3

        # Execute ProjectService.purge_project
        p_service = ProjectService(
            project_repo=project_repo,
            member_repo=member_repo,
            audit_repo=audit_repo,
            secret_repo=None,
            credential_repo=cred_repo,
        )

        admin_member = ProjectMember(
            project_id=proj_id,
            user_id="user_admin_member",
            role=ProjectRole.ADMIN,
        )
        member_repo.members[(str(proj_id), "user_admin_member")] = admin_member

        # Non-owner member attempting purge raises ForbiddenError
        with pytest.raises(ForbiddenError):
            await p_service.purge_project(proj_id, user_id="user_admin_member")

        res = await p_service.purge_project(proj_id, user_id=owner_id)
        assert res["purged"] is True

        # Verify all credentials purged from repository
        creds_after, total_after = await cred_repo.list_by_project(proj_id)
        assert total_after == 0

        # Verify CREDENTIAL_PURGED audit log recorded
        cred_purge_logs = [log for log in audit_repo.logs if log.action == ProjectAuditAction.CREDENTIAL_PURGED]
        assert len(cred_purge_logs) == 1
        assert cred_purge_logs[0].payload["deleted_credentials_count"] == 3


# ==============================================================================
# 5. FastAPI Security Dependency Tests (ApiKeyAuth & Dual-Mode Auth)
# ==============================================================================


class TestApiKeyAuthentication:
    """Verifies get_api_key_auth dependency, tenant isolation, and scope checking."""

    @pytest.fixture
    def auth_env(self):
        cred_repo = InMemoryProjectCredentialRepository()
        project_repo = InMemoryProjectRepositoryFake()

        proj_a = Project(
            name="Project Alpha",
            slug="project-alpha",
            owner_id="user_a",
            status=ProjectStatus.ACTIVE,
            version=1,
        )
        proj_a.id = PydanticObjectId()
        project_repo.projects[str(proj_a.id)] = proj_a

        proj_b = Project(
            name="Project Beta",
            slug="project-beta",
            owner_id="user_b",
            status=ProjectStatus.ACTIVE,
            version=1,
        )
        proj_b.id = PydanticObjectId()
        project_repo.projects[str(proj_b.id)] = proj_b

        return {
            "cred_repo": cred_repo,
            "project_repo": project_repo,
            "proj_a": proj_a,
            "proj_b": proj_b,
        }

    @pytest.mark.asyncio
    async def test_valid_api_key_header(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        cred = await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Alpha Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read", "runs:write"],
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = ApiKeyAuth(required_scopes=["projects:read"])
        actor: AuthenticatedActor = await auth_checker._execute(
            request=mock_req,
            header_key=raw_key,
            authorization=None,
            cred_repo=cred_repo,
            project_repo=project_repo,
        )

        assert actor.actor_type == "credential"
        assert actor.identity_id == str(cred.id)
        assert actor.project_id == str(proj_a.id)

    @pytest.mark.asyncio
    async def test_project_isolation_boundary_rejected(self, auth_env):
        """Cross-project access: key bound to Project A used against Project B route returns 403."""
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]
        proj_b = auth_env["proj_b"]

        raw_key, kh, mk = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Alpha Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_b.id)}  # Attempting to access Project B
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = ApiKeyAuth()
        with pytest.raises(ProjectAccessDeniedError) as exc_info:
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )
        assert exc_info.value.code == "PROJECT_ACCESS_DENIED"

    @pytest.mark.asyncio
    async def test_missing_and_insufficient_scopes(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Read Only Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "POST"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        # Endpoint requires "secrets:resolve" which key lacks
        auth_checker = ApiKeyAuth(required_scopes=["secrets:resolve"])
        with pytest.raises(InsufficientScopeError) as exc_info:
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )
        assert exc_info.value.code == "INSUFFICIENT_SCOPE"

    @pytest.mark.asyncio
    async def test_revoked_key_rejected(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Revoked Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                status=CredentialStatus.REVOKED,
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = ApiKeyAuth()
        with pytest.raises(CredentialRevokedError) as exc_info:
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )
        assert exc_info.value.code == "CREDENTIAL_REVOKED"

    @pytest.mark.asyncio
    async def test_expired_key_rejected(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Expired Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = ApiKeyAuth()
        with pytest.raises(CredentialExpiredError) as exc_info:
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )
        assert exc_info.value.code == "CREDENTIAL_EXPIRED"

    @pytest.mark.asyncio
    async def test_invalid_key_format_and_missing_key(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = get_api_key_auth()

        # Missing key
        with pytest.raises(UnauthorizedError):
            await auth_checker._execute(
                request=mock_req,
                header_key=None,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

        # Invalid prefix
        with pytest.raises(InvalidCredentialError):
            await auth_checker._execute(
                request=mock_req,
                header_key="invalid_prefix_abc123456789",
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

    @pytest.mark.asyncio
    async def test_unknown_key_hash_rejected(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        raw_key, _, _ = generate_api_key("production")
        auth_checker = require_api_key_scopes("projects:read")

        with pytest.raises(InvalidCredentialError):
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

    @pytest.mark.asyncio
    async def test_parent_project_purged_or_deleted(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]

        purged_proj = Project(
            name="Purged",
            slug="purged",
            owner_id="user_p",
            status=ProjectStatus.PURGED,
            version=1,
        )
        purged_proj.id = PydanticObjectId()
        project_repo.projects[str(purged_proj.id)] = purged_proj

        deleted_proj = Project(
            name="Deleted",
            slug="deleted",
            owner_id="user_d",
            status=ProjectStatus.SOFT_DELETED,
            version=1,
        )
        deleted_proj.id = PydanticObjectId()
        project_repo.projects[str(deleted_proj.id)] = deleted_proj

        raw_key_p, kh_p, mk_p = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=purged_proj.id,
                name="Purged Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk_p,
                key_hash=kh_p,
                scopes=["projects:read"],
                created_by="user_p",
                updated_by="user_p",
            )
        )

        raw_key_d, kh_d, mk_d = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=deleted_proj.id,
                name="Deleted Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk_d,
                key_hash=kh_d,
                scopes=["projects:read"],
                created_by="user_d",
                updated_by="user_d",
            )
        )

        mock_req_p = MagicMock(spec=Request)
        mock_req_p.path_params = {"project_id": str(purged_proj.id)}
        mock_req_p.query_params = {}
        mock_req_p.method = "GET"
        mock_req_p.client.host = "127.0.0.1"
        mock_req_p.state = MagicMock()

        auth_checker = ApiKeyAuth()
        with pytest.raises(NotFoundError):
            await auth_checker._execute(
                request=mock_req_p,
                header_key=raw_key_p,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

        mock_req_d = MagicMock(spec=Request)
        mock_req_d.path_params = {"project_id": str(deleted_proj.id)}
        mock_req_d.query_params = {}
        mock_req_d.method = "GET"
        mock_req_d.client.host = "127.0.0.1"
        mock_req_d.state = MagicMock()

        with pytest.raises(ProjectDeletedError):
            await auth_checker._execute(
                request=mock_req_d,
                header_key=raw_key_d,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

    @pytest.mark.asyncio
    async def test_dual_mode_auth(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Dual Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                created_by="user_a",
                updated_by="user_a",
            )
        )

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.headers = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        dual_auth = get_authenticated_context(["projects:read"])
        assert isinstance(dual_auth, AuthenticatedContextAuth)

        # 1. Machine API Key auth via X-Axion-Api-Key
        actor_machine = await dual_auth._execute(
            request=mock_req,
            header_key=raw_key,
            authorization=None,
            cred_repo=cred_repo,
            project_repo=project_repo,
        )
        assert actor_machine.actor_type == "credential"
        assert actor_machine.project_id == str(proj_a.id)

        # 2. Machine API Key auth via Authorization: Bearer axion_live_...
        actor_bearer = await dual_auth._execute(
            request=mock_req,
            header_key=None,
            authorization=f"Bearer {raw_key}",
            cred_repo=cred_repo,
            project_repo=project_repo,
        )
        assert actor_bearer.actor_type == "credential"

        # 3. Missing authentication
        with pytest.raises(UnauthorizedError):
            await dual_auth._execute(
                request=mock_req,
                header_key=None,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )

    @pytest.mark.asyncio
    async def test_rate_limit_rpm_exceeded(self, auth_env):
        cred_repo = auth_env["cred_repo"]
        project_repo = auth_env["project_repo"]
        proj_a = auth_env["proj_a"]

        raw_key, kh, mk = generate_api_key("production")
        cred = await cred_repo.create(
            ProjectCredential(
                project_id=proj_a.id,
                name="Rate Limited Key",
                environment="production",
                key_prefix="axion_live_",
                masked_key=mk,
                key_hash=kh,
                scopes=["projects:read"],
                rate_limit_rpm=2,  # Limit: 2 req/min
                created_by="user_a",
                updated_by="user_a",
            )
        )
        assert cred.rate_limit_rpm == 2

        mock_req = MagicMock(spec=Request)
        mock_req.path_params = {"project_id": str(proj_a.id)}
        mock_req.query_params = {}
        mock_req.method = "GET"
        mock_req.client.host = "127.0.0.1"
        mock_req.state = MagicMock()

        auth_checker = ApiKeyAuth()

        # 1st request -> ok
        await auth_checker._execute(
            request=mock_req,
            header_key=raw_key,
            authorization=None,
            cred_repo=cred_repo,
            project_repo=project_repo,
        )
        # 2nd request -> ok
        await auth_checker._execute(
            request=mock_req,
            header_key=raw_key,
            authorization=None,
            cred_repo=cred_repo,
            project_repo=project_repo,
        )
        # 3rd request -> exceeds 2 rpm limit
        with pytest.raises(RateLimitExceededError):
            await auth_checker._execute(
                request=mock_req,
                header_key=raw_key,
                authorization=None,
                cred_repo=cred_repo,
                project_repo=project_repo,
            )


# ==============================================================================
# 6. HTTP API Endpoint Tests via TestClient
# ==============================================================================


@pytest.fixture
def endpoint_test_setup():
    """Sets up in-memory fakes and test client for credential API endpoints."""
    project_id = "507f1f77bcf86cd799439011"
    proj_oid = ObjectId(project_id)

    mock_p_repo = MagicMock()
    mock_m_repo = MagicMock()
    mock_cred_repo = InMemoryProjectCredentialRepository()
    mock_audit_repo = InMemoryAuditRepository()

    active_proj = Project(
        name="Active Platform",
        slug="active-platform",
        owner_id="user_owner",
        status=ProjectStatus.ACTIVE,
        version=1,
    )
    active_proj.id = proj_oid

    mock_p_repo.get_by_id_or_slug = AsyncMock(return_value=active_proj)
    mock_p_repo.get_by_id = AsyncMock(return_value=active_proj)

    # Owner membership by default
    owner_member = ProjectMember(
        project_id=proj_oid,
        user_id="user_owner",
        role=ProjectRole.OWNER,
    )
    mock_m_repo.get_membership = AsyncMock(return_value=owner_member)

    cred_service = ProjectCredentialService(
        credential_repo=mock_cred_repo,
        project_repo=mock_p_repo,
        audit_repo=mock_audit_repo,
    )

    owner_user = make_actor_user(user_id="user_owner")

    app.dependency_overrides[get_current_user] = lambda: owner_user
    app.dependency_overrides[get_project_repository] = lambda: mock_p_repo
    app.dependency_overrides[get_project_member_repository] = lambda: mock_m_repo
    app.dependency_overrides[get_credential_service] = lambda: cred_service
    app.dependency_overrides[get_credential_repository] = lambda: mock_cred_repo
    app.dependency_overrides[get_project_audit_repository] = lambda: mock_audit_repo

    client = TestClient(app)

    yield {
        "client": client,
        "project": active_proj,
        "cred_service": cred_service,
        "cred_repo": mock_cred_repo,
        "project_repo": mock_p_repo,
        "member_repo": mock_m_repo,
        "owner_user": owner_user,
    }

    app.dependency_overrides.clear()


class TestCredentialApiEndpoints:
    """Verifies all REST API endpoints under /api/v1/projects/{project_id}/credentials."""

    def test_create_credential_endpoint_201_and_one_time_raw_key(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        payload = {
            "name": "Production Agent",
            "description": "Autonomous deployment agent",
            "environment": "production",
            "scopes": ["runs:write", "projects:read"],
            "rate_limit_rpm": 200,
        }
        res = client.post(f"/api/v1/projects/{project.id}/credentials", json=payload)
        assert res.status_code == status.HTTP_201_CREATED

        data = res.json()["data"]
        assert data["name"] == "Production Agent"
        assert data["raw_key"].startswith("axion_live_")
        assert data["masked_key"].startswith("axion_live_")
        assert data["status"] == "active"
        assert data["revision"] == 1

    def test_create_credential_duplicate_name_returns_409(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        payload = {
            "name": "Unique Worker",
            "environment": "production",
            "scopes": ["runs:write"],
        }
        # First creation succeeds
        res1 = client.post(f"/api/v1/projects/{project.id}/credentials", json=payload)
        assert res1.status_code == status.HTTP_201_CREATED

        # Duplicate creation returns 409
        res2 = client.post(f"/api/v1/projects/{project.id}/credentials", json=payload)
        assert res2.status_code == status.HTTP_409_CONFLICT
        assert res2.json()["error"]["code"] == "CREDENTIAL_NAME_EXISTS"

    def test_create_credential_role_restriction(self, endpoint_test_setup):
        """VIEWER role cannot create credentials (403 Forbidden)."""
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]
        mock_m_repo = endpoint_test_setup["member_repo"]

        # Downgrade caller to VIEWER
        viewer_member = ProjectMember(
            project_id=project.id,
            user_id="user_owner",
            role=ProjectRole.VIEWER,
        )
        mock_m_repo.get_membership = AsyncMock(return_value=viewer_member)

        payload = {"name": "Unauthorized Key", "scopes": ["projects:read"]}
        res = client.post(f"/api/v1/projects/{project.id}/credentials", json=payload)
        assert res.status_code == status.HTTP_403_FORBIDDEN

    def test_list_credentials_never_reveals_raw_key(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        # Create two credentials
        client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Key A", "scopes": ["projects:read"]},
        )
        client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Key B", "scopes": ["runs:write"]},
        )

        res = client.get(f"/api/v1/projects/{project.id}/credentials")
        assert res.status_code == status.HTTP_200_OK

        body = res.json()
        items = body["data"]["items"]
        assert len(items) == 2
        for item in items:
            assert "raw_key" not in item
            assert "masked_key" in item
            assert "key_prefix" in item

    def test_get_single_credential_metadata(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        create_res = client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Detail Key", "scopes": ["projects:read"]},
        )
        cred_id = create_res.json()["data"]["id"]

        res = client.get(f"/api/v1/projects/{project.id}/credentials/{cred_id}")
        assert res.status_code == status.HTTP_200_OK
        data = res.json()["data"]
        assert data["id"] == cred_id
        assert "raw_key" not in data

    def test_update_endpoint_does_not_exist_credentials_are_immutable(self, endpoint_test_setup):
        """Verifies requirement change: credentials CANNOT be updated. PATCH endpoint returns 405 Method Not Allowed."""
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        create_res = client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Immutable Key", "scopes": ["projects:read"]},
        )
        cred_id = create_res.json()["data"]["id"]

        patch_res = client.patch(
            f"/api/v1/projects/{project.id}/credentials/{cred_id}",
            json={"name": "Attempt Update"},
        )
        assert patch_res.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_revoke_credential_endpoint(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        create_res = client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Revoke Me", "scopes": ["projects:read"]},
        )
        cred_id = create_res.json()["data"]["id"]

        revoke_res = client.post(
            f"/api/v1/projects/{project.id}/credentials/{cred_id}/revoke",
            json={"expected_revision": 1, "reason": "Revocation test"},
        )
        assert revoke_res.status_code == status.HTTP_200_OK
        assert revoke_res.json()["data"]["status"] == "revoked"

        # Re-revocation returns 409 Conflict
        re_revoke_res = client.post(
            f"/api/v1/projects/{project.id}/credentials/{cred_id}/revoke",
            json={"expected_revision": 2},
        )
        assert re_revoke_res.status_code == status.HTTP_409_CONFLICT

    def test_delete_and_purge_credential_endpoint(self, endpoint_test_setup):
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        create_res = client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "Delete Target", "scopes": ["projects:read"]},
        )
        cred_id = create_res.json()["data"]["id"]

        # Attempt purge of active key -> 409 Conflict
        purge_active = client.delete(f"/api/v1/projects/{project.id}/credentials/{cred_id}?purge=true")
        assert purge_active.status_code == status.HTTP_409_CONFLICT

        # Soft-delete key -> 200 OK
        soft_del = client.delete(f"/api/v1/projects/{project.id}/credentials/{cred_id}")
        assert soft_del.status_code == status.HTTP_200_OK
        assert soft_del.json()["data"]["deleted"] is True

        # Purge soft-deleted key -> 200 OK
        purge_res = client.delete(f"/api/v1/projects/{project.id}/credentials/{cred_id}?purge=true")
        assert purge_res.status_code == status.HTTP_200_OK
        assert purge_res.json()["data"]["purged"] is True

    def test_rotate_endpoint_does_not_exist(self, endpoint_test_setup):
        """Verifies requirement change: credentials CANNOT be rotated. Route returns 404 or 405."""
        client: TestClient = endpoint_test_setup["client"]
        project: Project = endpoint_test_setup["project"]

        create_res = client.post(
            f"/api/v1/projects/{project.id}/credentials",
            json={"name": "No Rotation Key", "scopes": ["projects:read"]},
        )
        cred_id = create_res.json()["data"]["id"]

        res = client.post(
            f"/api/v1/projects/{project.id}/credentials/{cred_id}/rotate",
            json={"expected_revision": 1},
        )
        assert res.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_405_METHOD_NOT_ALLOWED)
