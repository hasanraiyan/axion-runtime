"""Request/response DTOs for Module 07 (SRS-07 Section 9). No plaintext secrets, ever."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.end_user import EndUserStatus, ProjectEndUser
from app.models.integration import (
    AuthProfile,
    AuthType,
    CredentialMode,
    EndUserAccess,
    Integration,
    IntegrationStatus,
    IntegrationType,
)
from app.models.tool import (
    ApprovalPolicy,
    Audience,
    BindingEffect,
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
    ToolDefinition,
    ToolSetting,
    ToolSyncState,
)
from app.models.tool_invocation import InvocationStatus, ToolInvocation

# ------------------------------------------------------------------ integrations


class IntegrationCreateRequest(BaseModel):
    type: IntegrationType
    slug: str = Field(..., pattern=r"^[a-z][a-z0-9_]{1,39}$")
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    config: Dict[str, Any] = Field(default_factory=dict)
    auth_profile: AuthProfile = Field(default_factory=AuthProfile)


class IntegrationUpdateRequest(BaseModel):
    revision: int = Field(..., ge=1, description="Expected revision for optimistic concurrency")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    config: Optional[Dict[str, Any]] = None
    auth_profile: Optional[AuthProfile] = None


class EndUserAccessRequest(BaseModel):
    access: EndUserAccess
    acknowledge_shared_identity: bool = False


class AuthProfileResponse(BaseModel):
    auth_type: AuthType
    credential_mode: CredentialMode
    secret_id: Optional[str] = None
    placement: Optional[str] = None
    name: Optional[str] = None
    prefix: Optional[str] = None
    username: Optional[str] = None
    header_names: List[str] = Field(default_factory=list, description="Header names only; values are never returned")


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    type: IntegrationType
    slug: str
    name: str
    description: Optional[str]
    config: Dict[str, Any]
    auth_profile: AuthProfileResponse
    status: IntegrationStatus
    status_reason: Optional[str]
    is_enabled: bool
    end_user_access: EndUserAccess
    last_discovery_at: Optional[datetime]
    health: Dict[str, Any]
    revision: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    is_deleted: bool = False

    @classmethod
    def from_model(cls, doc: Integration) -> "IntegrationResponse":
        profile = doc.auth_profile
        return cls(
            id=str(doc.id),
            project_id=str(doc.project_id),
            type=doc.type,
            slug=doc.slug,
            name=doc.name,
            description=doc.description,
            config=dict(doc.config),
            auth_profile=AuthProfileResponse(
                auth_type=profile.auth_type,
                credential_mode=profile.credential_mode,
                secret_id=str(profile.secret_id) if profile.secret_id else None,
                placement=profile.placement,
                name=profile.name,
                prefix=profile.prefix,
                username=profile.username,
                header_names=sorted(profile.headers.keys()),
            ),
            status=doc.status,
            status_reason=doc.status_reason,
            is_enabled=doc.is_enabled,
            end_user_access=doc.end_user_access,
            last_discovery_at=doc.last_discovery_at,
            health=doc.health.model_dump(mode="json"),
            revision=doc.revision,
            created_by=doc.created_by,
            created_at=doc.created_at,
            updated_at=doc.updated_at,
            is_deleted=doc.is_deleted,
        )


class ProbeResponse(BaseModel):
    healthy: bool
    status: str
    latency_ms: Optional[int] = None
    message: Optional[str] = None
    integration_status: IntegrationStatus
    server_info: Dict[str, Any] = Field(default_factory=dict)


class DiscoverySummaryResponse(BaseModel):
    added: List[str]
    changed: List[str]
    removed: List[str]
    unchanged: int
    total: int
    catalog_hash: str


class IntegrationOnboardingResponse(BaseModel):
    integration: IntegrationResponse
    probe: Optional[ProbeResponse] = None
    discovery: Optional[DiscoverySummaryResponse] = None
    warning: Optional[str] = None


# ------------------------------------------------------------------------ tools


class ToolSettingResponse(BaseModel):
    is_enabled: bool
    approved_hash: Optional[str]
    approval_policy: ApprovalPolicy
    description_override: Optional[str]
    locked_arguments: Dict[str, Any]
    default_arguments: Dict[str, Any]
    context_arguments: Dict[str, str]
    timeout_seconds: Optional[int]
    rate_limit_per_minute: Optional[int]
    per_end_user_rate_limit_per_minute: Optional[int]
    revision: int

    @classmethod
    def from_model(cls, doc: ToolSetting) -> "ToolSettingResponse":
        return cls(
            is_enabled=doc.is_enabled,
            approved_hash=doc.approved_hash,
            approval_policy=doc.approval_policy,
            description_override=doc.description_override,
            locked_arguments=dict(doc.locked_arguments),
            default_arguments=dict(doc.default_arguments),
            context_arguments=dict(doc.context_arguments),
            timeout_seconds=doc.timeout_seconds,
            rate_limit_per_minute=doc.rate_limit_per_minute,
            per_end_user_rate_limit_per_minute=doc.per_end_user_rate_limit_per_minute,
            revision=doc.revision,
        )


class ToolResponse(BaseModel):
    tool_key: str
    integration_id: str
    upstream_name: str
    title: Optional[str]
    description: str
    input_schema: Dict[str, Any]
    output_schema: Optional[Dict[str, Any]]
    annotations: Dict[str, Optional[bool]]
    ui: Optional[Dict[str, Any]]
    sync_state: ToolSyncState
    definition_hash: str
    needs_approval: bool = Field(description="True when the current definition has not been approved")
    setting: ToolSettingResponse

    @classmethod
    def from_models(cls, definition: ToolDefinition, setting: ToolSetting) -> "ToolResponse":
        return cls(
            tool_key=definition.tool_key,
            integration_id=str(definition.integration_id),
            upstream_name=definition.upstream_name,
            title=definition.title,
            description=definition.description,
            input_schema=definition.input_schema,
            output_schema=definition.output_schema,
            annotations=definition.annotations.model_dump(),
            ui=definition.ui.model_dump(mode="json") if definition.ui else None,
            sync_state=definition.sync_state,
            definition_hash=definition.definition_hash,
            needs_approval=setting.approved_hash != definition.definition_hash,
            setting=ToolSettingResponse.from_model(setting),
        )


class ToolSettingUpdateRequest(BaseModel):
    revision: int = Field(..., ge=1)
    is_enabled: Optional[bool] = None
    approval_policy: Optional[ApprovalPolicy] = None
    description_override: Optional[str] = Field(default=None, max_length=8000)
    locked_arguments: Optional[Dict[str, Any]] = None
    default_arguments: Optional[Dict[str, Any]] = None
    context_arguments: Optional[Dict[str, str]] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=300)
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1)
    per_end_user_rate_limit_per_minute: Optional[int] = Field(default=None, ge=1)


# -------------------------------------------------------------------- bindings


class BindingRule(BaseModel):
    target_type: BindingTargetType
    target_id: str = Field(..., min_length=1, max_length=200)
    effect: BindingEffect = BindingEffect.ALLOW
    approval_policy_override: Optional[ApprovalPolicy] = None


class BindingReplaceRequest(BaseModel):
    subject_type: BindingSubjectType
    subject_id: Optional[str] = Field(default=None, max_length=200)
    audience: List[Audience] = Field(default_factory=lambda: [Audience.MEMBERS])
    bindings: List[BindingRule] = Field(default_factory=list, max_length=500)


class BindingResponse(BaseModel):
    subject_type: BindingSubjectType
    subject_id: Optional[str]
    audience: List[Audience]
    target_type: BindingTargetType
    target_id: str
    effect: BindingEffect
    approval_policy_override: Optional[ApprovalPolicy]

    @classmethod
    def from_model(cls, doc: ToolBinding) -> "BindingResponse":
        return cls(
            subject_type=doc.subject_type,
            subject_id=doc.subject_id,
            audience=doc.audience,
            target_type=doc.target_type,
            target_id=doc.target_id,
            effect=doc.effect,
            approval_policy_override=doc.approval_policy_override,
        )


# ------------------------------------------------------------------ end users


class EndUserAssertRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=200)
    email: Optional[str] = Field(default=None, max_length=320)
    attributes: Optional[Dict[str, str]] = None


class EndUserResponse(BaseModel):
    id: str
    external_id: str
    display_name: Optional[str]
    email: Optional[str]
    attributes: Dict[str, str]
    status: EndUserStatus
    first_seen_at: datetime
    last_seen_at: datetime

    @classmethod
    def from_model(cls, doc: ProjectEndUser) -> "EndUserResponse":
        return cls(
            id=str(doc.id),
            external_id=doc.external_id,
            display_name=doc.display_name,
            email=doc.email,
            attributes=dict(doc.attributes),
            status=doc.status,
            first_seen_at=doc.first_seen_at,
            last_seen_at=doc.last_seen_at,
        )


class EndUserSessionRequest(BaseModel):
    ttl_seconds: int = Field(default=600, ge=60, le=3600)
    capabilities: List[str] = Field(default_factory=lambda: ["connections:own", "apps:use"])


class EndUserSessionResponse(BaseModel):
    token: str
    expires_in: int
    end_user_id: str


# --------------------------------------------------------------------- runtime


class ToolsetRequest(BaseModel):
    agent_id: Optional[str] = Field(default=None, max_length=200)
    end_user_external_id: Optional[str] = Field(default=None, max_length=255)


class ModelVisibleTool(BaseModel):
    tool_key: str
    description: str
    input_schema: Dict[str, Any]
    annotations: Dict[str, Optional[bool]]
    approval_policy: ApprovalPolicy
    ui: Optional[Dict[str, Any]] = None


class ToolsetExclusion(BaseModel):
    tool_key: Optional[str] = None
    integration: Optional[str] = None
    reason: str


class AuthRequiredEntry(BaseModel):
    integration_id: str
    integration: str
    reason: str
    connect_available: bool = False


class ToolsetResponse(BaseModel):
    toolset_version: str
    tools: List[ModelVisibleTool]
    excluded: List[ToolsetExclusion]
    auth_required: List[AuthRequiredEntry]


class InvokeRequest(BaseModel):
    tool_key: str = Field(..., min_length=3, max_length=160)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_id: Optional[str] = Field(default=None, max_length=200)
    run_id: Optional[str] = Field(default=None, max_length=200)
    end_user_external_id: Optional[str] = Field(default=None, max_length=255)
    idempotency_key: Optional[str] = Field(default=None, max_length=200)
    dry_run: bool = False
    approval_token: Optional[str] = Field(default=None, max_length=2000)
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=300)


class ContentBlockResponse(BaseModel):
    type: str
    text: Optional[str] = None
    data: Any = None
    mime_type: Optional[str] = None


class InvokeResponse(BaseModel):
    status: InvocationStatus
    is_error: bool
    content: List[ContentBlockResponse]
    structured_content: Any = None
    error_code: Optional[str] = None
    message: Optional[str] = None
    retryable: bool = False
    model_correctable: bool = False
    latency_ms: Optional[int] = None
    invocation_id: Optional[str] = None
    ui: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class ApprovalIssueRequest(BaseModel):
    tool_key: str = Field(..., min_length=3, max_length=160)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    end_user_external_id: Optional[str] = Field(default=None, max_length=255)
    member_id: Optional[str] = Field(default=None, max_length=200, description="Clerk id of the member the call is for")
    ttl_seconds: int = Field(default=300, ge=30, le=900)


class ApprovalIssueResponse(BaseModel):
    approval_token: str
    expires_in: int


class InvocationRecordResponse(BaseModel):
    id: str
    tool_key: str
    status: InvocationStatus
    origin: str
    dry_run: bool
    actor: Dict[str, Any]
    subject: Dict[str, Any]
    arguments_redacted: Dict[str, Any]
    result_summary: Dict[str, Any]
    latency_ms: Optional[int]
    started_at: datetime

    @classmethod
    def from_model(cls, doc: ToolInvocation) -> "InvocationRecordResponse":
        return cls(
            id=str(doc.id),
            tool_key=doc.tool_key,
            status=doc.status,
            origin=doc.origin,
            dry_run=doc.dry_run,
            actor=doc.actor,
            subject=doc.subject,
            arguments_redacted=doc.arguments_redacted,
            result_summary=doc.result_summary,
            latency_ms=doc.latency_ms,
            started_at=doc.started_at,
        )


class IntegrationTypeInfo(BaseModel):
    key: str
    supported_auth_types: List[str]


class NativeProviderInfo(BaseModel):
    key: str
    name: str
    description: str
    tools: List[str]


class IntegrationTypesResponse(BaseModel):
    types: List[IntegrationTypeInfo]
    native_providers: List[NativeProviderInfo]


# ----------------------------------------------------------------- connections (phase 2)
from pydantic import SecretStr  # noqa: E402

from app.models.connection import (  # noqa: E402
    ConnectionStatus,
    ConnectionSubjectType,
    CredentialKind,
    IntegrationConnection,
    ProjectToolPolicy,
)


class ConnectionResponse(BaseModel):
    """Connection *metadata* only. Credentials are never returned to any caller."""

    id: str
    integration_id: str
    integration_slug: Optional[str] = None
    integration_name: Optional[str] = None
    subject_type: ConnectionSubjectType
    subject_id: Optional[str]
    credential_kind: CredentialKind
    status: ConnectionStatus
    granted_scopes: List[str]
    external_account: Dict[str, Any]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(
        cls, doc: IntegrationConnection, integration: Optional[Integration] = None
    ) -> "ConnectionResponse":
        return cls(
            id=str(doc.id),
            integration_id=str(doc.integration_id),
            integration_slug=integration.slug if integration else None,
            integration_name=integration.name if integration else None,
            subject_type=doc.subject_type,
            subject_id=doc.subject_id,
            credential_kind=doc.credential_kind,
            status=doc.status,
            granted_scopes=list(doc.granted_scopes),
            external_account=dict(doc.external_account),
            expires_at=doc.expires_at,
            last_used_at=doc.last_used_at,
            last_error=doc.last_error,
            created_at=doc.created_at,
            updated_at=doc.updated_at,
        )


class AuthorizeRequest(BaseModel):
    scope: str = Field(default="self", pattern="^(self|project)$", description="'project' connects the shared credential (admins)")
    return_url: Optional[str] = Field(default=None, max_length=2000)


class AuthorizeResponse(BaseModel):
    authorization_url: str


class ConnectLinkRequest(BaseModel):
    end_user_external_id: Optional[str] = Field(default=None, max_length=255)
    member_id: Optional[str] = Field(default=None, max_length=200)
    return_url: Optional[str] = Field(default=None, max_length=2000)


class ConnectLinkResponse(BaseModel):
    connect_url: str
    expires_in: int


class StaticCredentialRequest(BaseModel):
    credential: SecretStr = Field(..., min_length=1, max_length=4096, description="The user's own API key or token")


class ConnectOutcomeResponse(BaseModel):
    success: bool
    integration: Optional[str] = None
    error: Optional[str] = None


class ToolPolicyResponse(BaseModel):
    allowed_return_origins: List[str]
    end_user_connect_enabled: bool
    connect_link_ttl_seconds: int
    revision: int

    @classmethod
    def from_model(cls, doc: ProjectToolPolicy) -> "ToolPolicyResponse":
        return cls(
            allowed_return_origins=list(doc.allowed_return_origins),
            end_user_connect_enabled=doc.end_user_connect_enabled,
            connect_link_ttl_seconds=doc.connect_link_ttl_seconds,
            revision=doc.revision,
        )


class ToolPolicyUpdateRequest(BaseModel):
    revision: int = Field(..., ge=1)
    allowed_return_origins: Optional[List[str]] = Field(default=None, max_length=20)
    end_user_connect_enabled: Optional[bool] = None
    connect_link_ttl_seconds: Optional[int] = Field(default=None, ge=60, le=3600)


# ------------------------------------------------------------------------- MCP Apps
from app.models.app_resource import AppResource, AppSyncState  # noqa: E402


class AppResourceResponse(BaseModel):
    """App metadata for admins. The HTML itself is never included here."""

    id: str
    integration_id: str
    uri: str
    mime_type: Optional[str]
    size_bytes: int
    content_hash: str
    declared_csp: Dict[str, List[str]]
    declared_permissions: List[str]
    approved: bool = Field(description="True when the current content hash is the approved one")
    approved_hash: Optional[str]
    approved_csp: Dict[str, List[str]]
    approved_permissions: List[str]
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    sync_state: AppSyncState
    status_message: Optional[str]
    fetched_at: datetime
    revision: int

    @classmethod
    def from_model(cls, doc: AppResource) -> "AppResourceResponse":
        return cls(
            id=str(doc.id), integration_id=str(doc.integration_id), uri=doc.uri, mime_type=doc.mime_type,
            size_bytes=doc.size_bytes, content_hash=doc.content_hash, declared_csp=doc.declared_csp,
            declared_permissions=doc.declared_permissions, approved=doc.is_approved, approved_hash=doc.approved_hash,
            approved_csp=doc.approved_csp, approved_permissions=doc.approved_permissions, approved_by=doc.approved_by,
            approved_at=doc.approved_at, sync_state=doc.sync_state, status_message=doc.status_message,
            fetched_at=doc.fetched_at, revision=doc.revision,
        )


class AppSyncResponse(BaseModel):
    synced: List[str]
    changed: List[str]
    unavailable: List[Dict[str, str]]


class AppApproveRequest(BaseModel):
    content_hash: str = Field(..., min_length=64, max_length=64, description="The hash the admin reviewed")
    csp: Dict[str, List[str]] = Field(default_factory=dict, description="Domains to allow, per CSP category; others are denied")
    permissions: List[str] = Field(default_factory=list, description="Browser permissions to allow; others are denied")


class AppContentResponse(BaseModel):
    resource_id: str
    uri: str
    mime_type: Optional[str]
    html: str
    content_hash: str
    csp: Dict[str, List[str]]
    permissions: List[str]


class AppToolCallRequest(BaseModel):
    resource_id: str = Field(..., min_length=1, max_length=64)
    tool_key: str = Field(..., min_length=3, max_length=160)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = Field(default=None, max_length=200)


class AppResourceReadRequest(BaseModel):
    resource_id: str = Field(..., min_length=1, max_length=64)
    uri: str = Field(..., min_length=1, max_length=2000)


class ResourceReadResponse(BaseModel):
    uri: str
    mime_type: Optional[str]
    text: Optional[str] = None
    blob_base64: Optional[str] = None
    size_bytes: int


class ResourceInfoResponse(BaseModel):
    uri: str
    name: str
    description: Optional[str]
    mime_type: Optional[str]
    is_template: bool


class PromptInfoResponse(BaseModel):
    name: str
    description: Optional[str]
    arguments: List[Dict[str, Any]]
