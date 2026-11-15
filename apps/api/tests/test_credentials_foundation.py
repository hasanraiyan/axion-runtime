from datetime import datetime, timezone
from beanie import PydanticObjectId

from app.core.exceptions import (
    CredentialExpiredError,
    CredentialRevisionConflictError,
    CredentialRevokedError,
    DuplicateCredentialNameError,
    InsufficientScopeError,
    InvalidCredentialError,
    ProjectAccessDeniedError,
)
from app.models.credential import CredentialStatus, ProjectCredential
from app.models.project import ProjectAuditAction
from app.schemas.auth import AuthenticatedActor
from app.schemas.credential import (
    CredentialCreate,
    CredentialCreateRequest,
    CredentialCreateResponse,
    CredentialListResponse,
    CredentialResponse,
    RevokeRequest,
)


def test_credential_status_enum():
    assert CredentialStatus.ACTIVE.value == "active"
    assert CredentialStatus.REVOKED.value == "revoked"
    assert CredentialStatus.EXPIRED.value == "expired"


def test_project_audit_action_credential_enum():
    assert ProjectAuditAction.CREDENTIAL_CREATED.value == "credential.created"
    assert ProjectAuditAction.CREDENTIAL_UPDATED.value == "credential.updated"
    assert ProjectAuditAction.CREDENTIAL_REVOKED.value == "credential.revoked"
    assert ProjectAuditAction.CREDENTIAL_DELETED.value == "credential.deleted"
    assert ProjectAuditAction.CREDENTIAL_PURGED.value == "credential.purged"


def test_project_credential_model_metadata():
    assert ProjectCredential.Settings.name == "project_credentials"
    index_names = [idx.document["name"] for idx in ProjectCredential.Settings.indexes]
    expected_indexes = [
        "idx_credentials_key_hash_unique",
        "idx_credentials_project_name_unique",
        "idx_credentials_project_status",
        "idx_credentials_project_created",
        "idx_credentials_active_expiration",
    ]
    for exp in expected_indexes:
        assert exp in index_names


def test_credential_partial_index_filters_use_supported_operators():
    """Regression: `expires_at: {"$ne": None}` makes init_beanie fail with
    CannotCreateIndex (code 67), which aborts startup index creation for *all*
    models. Partial filters must only use operators MongoDB supports."""
    allowed_operators = {"$eq", "$exists", "$gt", "$gte", "$lt", "$lte", "$type", "$and", "$or", "$in"}

    def collect_operators(node):
        found = set()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.startswith("$"):
                    found.add(key)
                found |= collect_operators(value)
        elif isinstance(node, list):
            for child in node:
                found |= collect_operators(child)
        return found

    filters = {}
    for idx in ProjectCredential.Settings.indexes:
        document = idx.document
        partial = document.get("partialFilterExpression")
        if partial is not None:
            filters[document["name"]] = partial

    assert filters, "expected at least one partial index on ProjectCredential"
    for name, partial in filters.items():
        operators = set(collect_operators(partial))
        unsupported = operators - allowed_operators
        assert not unsupported, f"index {name} uses unsupported partial filter operators: {unsupported}"

    expiration = filters["idx_credentials_active_expiration"]
    assert expiration.get("status") == "active"
    # $ne compiles to $not, which MongoDB rejects inside partialFilterExpression.
    assert "$ne" not in repr(expiration)
    assert "$not" not in repr(expiration)


def test_credential_domain_exceptions():
    err1 = InvalidCredentialError()
    assert err1.status_code == 401
    assert err1.code == "INVALID_CREDENTIAL"

    err2 = CredentialRevokedError()
    assert err2.status_code == 401
    assert err2.code == "CREDENTIAL_REVOKED"

    err3 = CredentialExpiredError()
    assert err3.status_code == 401
    assert err3.code == "CREDENTIAL_EXPIRED"

    err4 = ProjectAccessDeniedError()
    assert err4.status_code == 403
    assert err4.code == "PROJECT_ACCESS_DENIED"

    err5 = InsufficientScopeError(required_scope="secrets:resolve")
    assert err5.status_code == 403
    assert err5.code == "INSUFFICIENT_SCOPE"
    assert "secrets:resolve" in err5.message

    err6 = DuplicateCredentialNameError(name="runner-key")
    assert err6.status_code == 409
    assert err6.code == "CREDENTIAL_NAME_EXISTS"
    assert "runner-key" in err6.message

    err7 = CredentialRevisionConflictError()
    assert err7.status_code == 409
    assert err7.code == "CREDENTIAL_REVISION_CONFLICT"


def test_credential_schemas():
    # Create request
    create_req = CredentialCreateRequest(
        name="Test Key",
        environment="production",
        scopes=["projects:read", "runs:write"],
    )
    assert create_req.name == "Test Key"
    assert CredentialCreate is CredentialCreateRequest

    # Revoke request
    revoke_req = RevokeRequest(expected_revision=2, reason="Compromised")
    assert revoke_req.expected_revision == 2
    assert revoke_req.reason == "Compromised"

    # Response mapping
    proj_id = PydanticObjectId()
    cred_id = PydanticObjectId()
    now = datetime.now(timezone.utc)
    cred = ProjectCredential.model_construct(
        id=cred_id,
        project_id=proj_id,
        name="Runner Key",
        description="Runner description",
        environment="production",
        key_prefix="axion_live_",
        masked_key="axion_live_abcd...wxyz",
        key_hash="abc123hash",
        scopes=["projects:read"],
        rate_limit_rpm=None,
        status=CredentialStatus.ACTIVE,
        revision=1,
        expires_at=None,
        revoked_at=None,
        last_used_at=None,
        total_uses=0,
        created_by="user_123",
        updated_by="user_123",
        created_at=now,
        updated_at=now,
    )
    resp = CredentialResponse.from_model(cred)
    assert resp.id == str(cred_id)
    assert resp.project_id == str(proj_id)
    assert resp.name == "Runner Key"
    assert resp.status == CredentialStatus.ACTIVE

    create_resp = CredentialCreateResponse(
        **resp.model_dump(),
        raw_key="axion_live_secret1234567890",
    )
    assert create_resp.raw_key == "axion_live_secret1234567890"

    list_resp = CredentialListResponse(items=[resp], total=1, page=1, page_size=10)
    assert list_resp.total == 1
    assert len(list_resp.items) == 1

    actor = AuthenticatedActor(
        actor_type="credential",
        identity_id=str(cred_id),
        project_id=str(proj_id),
        scopes=["projects:read"],
    )
    assert actor.actor_type == "credential"
    assert actor.identity_id == str(cred_id)
