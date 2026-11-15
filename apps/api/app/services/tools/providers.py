"""
Composition root for Module 07 (Dependency Inversion): the only place that wires concrete
repositories, adapters, and infrastructure into services. Services themselves depend only on
ports, so tests build a ``ToolsContainer`` from fakes (``build_tools_container``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import Depends

from app.core.config import settings as app_settings
from app.core.crypto import CryptoService, get_crypto_service
from app.core.outbound import OutboundUrlGuard, get_outbound_url_guard
from app.core.tools.events import InProcessEventBus, McpListChanged, McpSessionsInvalidated, ToolsetChanged, get_event_bus
from app.core.tools.registry import AdapterRegistry, AuthStrategyRegistry
from app.core.tools.ports import OAuthFlowPort
from app.core.tools.token_cache import TokenCache
from app.core.tools.resilience import CircuitBreaker, ConcurrencyLimiter, IdempotencyStore, KeyedLocks, SlidingWindowRateLimiter
from app.core.tools.signing import TokenSigner
from app.integrations.adapters import McpAdapter, NativeAdapter
from app.integrations.auth import build_default_auth_registry
from app.integrations.mcp_client import McpConnectorPort, SdkMcpConnector
from app.integrations.mcp_pool import McpSessionPool, PooledMcpConnector
from app.integrations.native import NativeProviderRegistry, build_default_native_registry
from app.integrations.oauth import OAuthFlowClient
from app.repositories.end_user_repository import (
    get_end_user_repository,
    get_tool_invocation_repository,
)
from app.repositories.app_resource_repository import get_app_resource_repository
from app.repositories.connection_repository import (
    get_connect_session_repository,
    get_connection_repository,
    get_oauth_client_repository,
    get_tool_policy_repository,
)
from app.repositories.integration_repository import get_integration_repository
from app.repositories.project_audit_repository import get_project_audit_repository
from app.repositories.project_repository import get_project_repository
from app.repositories.secret_repository import get_secret_repository
from app.repositories.tool_repository import (
    get_tool_binding_repository,
    get_tool_definition_repository,
    get_tool_setting_repository,
)
from app.services.tools.app_resources import McpAppService
from app.services.tools.binding_service import BindingService
from app.services.tools.catalog_sync import CatalogSyncSubscriber
from app.services.tools.common import ProjectAuditAdapter, ProjectLifecycle, ProjectSecretReader
from app.services.tools.connect_flow import ConnectFlowService, ToolPolicyService
from app.services.tools.connections import ConnectionService, ConnectionTokenService, TokenCipher
from app.services.tools.credentials import CredentialBuilder
from app.services.tools.discovery_service import DiscoveryService
from app.services.tools.end_user_service import EndUserService
from app.services.tools.gateway import InvocationRecorder, ToolExecutionGateway
from app.services.tools.gateway_stages import build_stages
from app.services.tools.health_service import IntegrationHealthService
from app.services.tools.integration_service import IntegrationService
from app.services.tools.onboarding import IntegrationOnboardingService
from app.services.tools.policy_reader import PolicyCache, PolicyReader
from app.services.tools.principal import ApprovalService, PrincipalResolver
from app.services.tools.purge import ToolCascadePurger
from app.services.tools.toolset import ToolsetResolver
from app.services.tools.toolset_cache import ToolsetCache
from app.services.tools.tool_service import ToolCatalogService, ToolSettingService


@dataclass
class SharedToolState:
    """Process-wide state that must outlive a single request."""

    breaker: CircuitBreaker
    limiter: SlidingWindowRateLimiter
    idempotency: IdempotencyStore
    events: InProcessEventBus
    native: NativeProviderRegistry
    locks: KeyedLocks
    mcp_pool: McpSessionPool = field(default_factory=McpSessionPool)
    policy_cache: PolicyCache = field(default_factory=PolicyCache)
    toolset_cache: ToolsetCache = field(default_factory=ToolsetCache)
    concurrency: ConcurrencyLimiter = field(default_factory=ConcurrencyLimiter)
    token_cache: TokenCache = field(default_factory=TokenCache)
    catalog_sync: Optional[CatalogSyncSubscriber] = None

    def __post_init__(self) -> None:
        # Every shared state wires its own cache to its own bus, exactly once.
        self.events.subscribe(ToolsetChanged, self.toolset_cache.on_toolset_changed)


_shared: Optional[SharedToolState] = None


def get_shared_tool_state() -> SharedToolState:
    global _shared
    if _shared is None:
        _shared = SharedToolState(
            breaker=CircuitBreaker(),
            limiter=SlidingWindowRateLimiter(),
            idempotency=IdempotencyStore(),
            events=get_event_bus(),
            native=build_default_native_registry(),
            locks=KeyedLocks(),
            mcp_pool=McpSessionPool(
                idle_ttl=app_settings.MCP_POOL_IDLE_SECONDS,
                per_user_idle_ttl=app_settings.MCP_POOL_PER_USER_IDLE_SECONDS,
                max_per_integration=app_settings.MCP_POOL_MAX_PER_INTEGRATION,
                max_total=app_settings.MCP_POOL_MAX_TOTAL,
            ),
        )
    return _shared


@dataclass
class ToolsContainer:
    lifecycle: ProjectLifecycle
    adapters: AdapterRegistry
    auth_registry: AuthStrategyRegistry
    native: NativeProviderRegistry
    integrations: IntegrationService
    health: IntegrationHealthService
    discovery: DiscoveryService
    onboarding: IntegrationOnboardingService
    catalog: ToolCatalogService
    tool_settings: ToolSettingService
    bindings: BindingService
    toolset: ToolsetResolver
    end_users: EndUserService
    principals: PrincipalResolver
    approvals: ApprovalService
    gateway: ToolExecutionGateway
    invocations: Any  # IToolInvocationRepository (read-only listing)
    connections: ConnectionService
    connect_flow: ConnectFlowService
    policy: ToolPolicyService
    apps: McpAppService


def _default_connector(guard: OutboundUrlGuard, shared: SharedToolState) -> McpConnectorPort:
    """The SDK connector that publishes list_changed events, served from the shared session pool when enabled."""

    async def publish_list_changed(integration: Any, kind: str) -> None:
        await shared.events.publish(McpListChanged(str(integration.project_id), str(integration.id), kind))

    inner = SdkMcpConnector(guard, on_list_changed=publish_list_changed)
    return PooledMcpConnector(inner, shared.mcp_pool) if app_settings.MCP_POOL_ENABLED else inner


def build_tools_container(
    *,
    project_repo: Any,
    secret_repo: Any,
    audit_repo: Any,
    crypto: CryptoService,
    integration_repo: Any,
    tool_repo: Any,
    setting_repo: Any,
    binding_repo: Any,
    end_user_repo: Any,
    invocation_repo: Any,
    guard: OutboundUrlGuard,
    shared: SharedToolState,
    signer: TokenSigner,
    connector: Optional[McpConnectorPort] = None,
    connection_repo: Any = None,
    session_repo: Any = None,
    oauth_client_repo: Any = None,
    policy_repo: Any = None,
    app_repo: Any = None,
    oauth: Optional[OAuthFlowPort] = None,
    public_base_url: str = "http://localhost:8000",
) -> ToolsContainer:
    audit = ProjectAuditAdapter(audit_repo)
    lifecycle = ProjectLifecycle(project_repo)
    events = shared.events

    adapters = AdapterRegistry()
    adapters.register(NativeAdapter(shared.native))
    adapters.register(McpAdapter(connector or _default_connector(guard, shared)))
    oauth_flow = oauth or OAuthFlowClient(guard)
    auth_registry = build_default_auth_registry(oauth_flow, shared.token_cache)

    secret_reader = ProjectSecretReader(secret_repo, crypto)
    cipher = TokenCipher(crypto)
    audit_port = audit
    connections = ConnectionService(
        lifecycle, connection_repo, integration_repo, oauth_client_repo, cipher, oauth_flow, audit_port, events=events
    )
    token_service = ConnectionTokenService(connection_repo, oauth_client_repo, integration_repo, cipher, oauth_flow, shared.locks)
    credentials = CredentialBuilder(auth_registry, secret_reader, token_service)
    integrations = IntegrationService(
        lifecycle, integration_repo, secret_repo, adapters, auth_registry, guard, audit, events, connections=connections
    )
    policy = ToolPolicyService(lifecycle, policy_repo, audit_port, cache=shared.policy_cache)
    policy_reader = PolicyReader(policy_repo, shared.policy_cache)

    health = IntegrationHealthService(lifecycle, integration_repo, adapters, credentials, audit, events)
    discovery = DiscoveryService(
        lifecycle, integration_repo, tool_repo, setting_repo, adapters, credentials, audit, events, policy_reader=policy_reader
    )
    catalog = ToolCatalogService(lifecycle, tool_repo, setting_repo)
    tool_settings = ToolSettingService(lifecycle, tool_repo, setting_repo, audit, events)
    bindings = BindingService(lifecycle, binding_repo, integration_repo, tool_repo, audit, events)
    toolset = ToolsetResolver(
        lifecycle, integration_repo, tool_repo, setting_repo, binding_repo, adapters,
        auth_registry=auth_registry, connections=connections, policy_reader=policy_reader,
        cache=shared.toolset_cache,
    )
    end_users = EndUserService(lifecycle, end_user_repo, signer, audit, events, invocation_repo, connections=connections)
    principals = PrincipalResolver(end_users)
    approvals = ApprovalService(signer, end_users, audit)
    stages = build_stages(
        toolset, end_users, signer, shared.limiter, shared.breaker, shared.idempotency, credentials, adapters, health,
        policy_reader=policy_reader, concurrency=shared.concurrency,
        default_concurrency=app_settings.TOOL_MAX_CONCURRENT_CALLS,
        concurrency_wait_seconds=app_settings.TOOL_CONCURRENCY_WAIT_SECONDS,
    )
    gateway = ToolExecutionGateway(stages, InvocationRecorder(invocation_repo, audit, policy_reader))
    apps = McpAppService(
        lifecycle, integration_repo, tool_repo, app_repo, adapters, credentials, gateway, shared.limiter, audit_port
    )
    onboarding = IntegrationOnboardingService(integrations, health, discovery, apps=apps)
    connect_flow = ConnectFlowService(
        lifecycle, integration_repo, adapters, auth_registry, oauth_client_repo, session_repo, policy, connections,
        oauth_flow, cipher, secret_reader, audit_port, public_base_url, post_connect=onboarding.verify,
    )

    return ToolsContainer(
        lifecycle=lifecycle,
        adapters=adapters,
        auth_registry=auth_registry,
        native=shared.native,
        integrations=integrations,
        health=health,
        discovery=discovery,
        onboarding=onboarding,
        catalog=catalog,
        tool_settings=tool_settings,
        bindings=bindings,
        toolset=toolset,
        end_users=end_users,
        principals=principals,
        approvals=approvals,
        gateway=gateway,
        invocations=invocation_repo,
        connections=connections,
        connect_flow=connect_flow,
        policy=policy,
        apps=apps,
    )


def build_default_container(crypto: CryptoService, guard: OutboundUrlGuard) -> ToolsContainer:
    """The fully wired Module 07 services over the real repositories."""
    return build_tools_container(
        project_repo=get_project_repository(),
        secret_repo=get_secret_repository(),
        audit_repo=get_project_audit_repository(),
        crypto=crypto,
        integration_repo=get_integration_repository(),
        tool_repo=get_tool_definition_repository(),
        setting_repo=get_tool_setting_repository(),
        binding_repo=get_tool_binding_repository(),
        end_user_repo=get_end_user_repository(),
        invocation_repo=get_tool_invocation_repository(),
        guard=guard,
        shared=get_shared_tool_state(),
        signer=TokenSigner(app_settings.AXION_MASTER_ENCRYPTION_KEY),
        connection_repo=get_connection_repository(),
        session_repo=get_connect_session_repository(),
        oauth_client_repo=get_oauth_client_repository(),
        policy_repo=get_tool_policy_repository(),
        app_repo=get_app_resource_repository(),
        public_base_url=app_settings.PUBLIC_API_BASE_URL,
    )


def get_tools_container(
    crypto: CryptoService = Depends(get_crypto_service),
    guard: OutboundUrlGuard = Depends(get_outbound_url_guard),
) -> ToolsContainer:
    """FastAPI dependency: the fully wired Module 07 services."""
    return build_default_container(crypto, guard)


def start_background_services() -> None:
    """
    Process-wide subscribers (idempotent): re-discover on MCP ``list_changed`` and close pooled sessions when an
    integration's credentials or endpoint change. Registered at the composition root, never inside a service.
    """
    shared = get_shared_tool_state()
    if shared.catalog_sync is not None:
        return
    subscriber = CatalogSyncSubscriber(
        lambda: build_default_container(get_crypto_service(), get_outbound_url_guard()),
        debounce=app_settings.MCP_LIST_CHANGED_DEBOUNCE_SECONDS,
    )
    shared.catalog_sync = subscriber
    shared.events.subscribe(McpListChanged, subscriber.handle)

    async def evict(event: McpSessionsInvalidated) -> None:
        await shared.mcp_pool.evict_integration(event.integration_id)

    shared.events.subscribe(McpSessionsInvalidated, evict)


async def stop_background_services() -> None:
    shared = get_shared_tool_state()
    if shared.catalog_sync is not None:
        await shared.catalog_sync.shutdown()
    await shared.mcp_pool.close_all()


def get_tool_cascade_purger() -> ToolCascadePurger:
    """Provider used by ProjectService to cascade purges into Module 07."""
    return ToolCascadePurger(
        invocation_repo=get_tool_invocation_repository(),
        binding_repo=get_tool_binding_repository(),
        setting_repo=get_tool_setting_repository(),
        tool_repo=get_tool_definition_repository(),
        end_user_repo=get_end_user_repository(),
        integration_repo=get_integration_repository(),
        audit=ProjectAuditAdapter(get_project_audit_repository()),
        connection_repo=get_connection_repository(),
        session_repo=get_connect_session_repository(),
        oauth_client_repo=get_oauth_client_repository(),
        policy_repo=get_tool_policy_repository(),
        app_repo=get_app_resource_repository(),
    )
