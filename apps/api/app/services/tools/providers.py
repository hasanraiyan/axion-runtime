"""
Composition root for Module 07 (Dependency Inversion): the only place that wires concrete
repositories, adapters, and infrastructure into services. Services themselves depend only on
ports, so tests build a ``ToolsContainer`` from fakes (``build_tools_container``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from fastapi import Depends

from app.core.config import settings as app_settings
from app.core.crypto import CryptoService, get_crypto_service
from app.core.outbound import OutboundUrlGuard, get_outbound_url_guard
from app.core.tools.events import InProcessEventBus, get_event_bus
from app.core.tools.registry import AdapterRegistry, AuthStrategyRegistry
from app.core.tools.resilience import CircuitBreaker, IdempotencyStore, SlidingWindowRateLimiter
from app.core.tools.signing import TokenSigner
from app.integrations.adapters import McpAdapter, NativeAdapter
from app.integrations.auth import build_default_auth_registry
from app.integrations.mcp_client import McpConnectorPort, SdkMcpConnector
from app.integrations.native import NativeProviderRegistry, build_default_native_registry
from app.repositories.end_user_repository import (
    get_end_user_repository,
    get_tool_invocation_repository,
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
from app.services.tools.binding_service import BindingService
from app.services.tools.common import ProjectAuditAdapter, ProjectLifecycle, ProjectSecretReader
from app.services.tools.credentials import CredentialBuilder
from app.services.tools.discovery_service import DiscoveryService
from app.services.tools.end_user_service import EndUserService
from app.services.tools.gateway import InvocationRecorder, ToolExecutionGateway
from app.services.tools.gateway_stages import build_stages
from app.services.tools.health_service import IntegrationHealthService
from app.services.tools.integration_service import IntegrationService
from app.services.tools.onboarding import IntegrationOnboardingService
from app.services.tools.principal import ApprovalService, PrincipalResolver
from app.services.tools.purge import ToolCascadePurger
from app.services.tools.toolset import ToolsetResolver
from app.services.tools.tool_service import ToolCatalogService, ToolSettingService


@dataclass
class SharedToolState:
    """Process-wide state that must outlive a single request."""

    breaker: CircuitBreaker
    limiter: SlidingWindowRateLimiter
    idempotency: IdempotencyStore
    events: InProcessEventBus
    native: NativeProviderRegistry


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
) -> ToolsContainer:
    audit = ProjectAuditAdapter(audit_repo)
    lifecycle = ProjectLifecycle(project_repo)
    events = shared.events

    adapters = AdapterRegistry()
    adapters.register(NativeAdapter(shared.native))
    adapters.register(McpAdapter(connector or SdkMcpConnector(guard)))
    auth_registry = build_default_auth_registry()

    credentials = CredentialBuilder(auth_registry, ProjectSecretReader(secret_repo, crypto))

    integrations = IntegrationService(lifecycle, integration_repo, secret_repo, adapters, auth_registry, guard, audit, events)
    health = IntegrationHealthService(lifecycle, integration_repo, adapters, credentials, audit, events)
    discovery = DiscoveryService(lifecycle, integration_repo, tool_repo, setting_repo, adapters, credentials, audit, events)
    onboarding = IntegrationOnboardingService(integrations, health, discovery)
    catalog = ToolCatalogService(lifecycle, tool_repo, setting_repo)
    tool_settings = ToolSettingService(lifecycle, tool_repo, setting_repo, audit, events)
    bindings = BindingService(lifecycle, binding_repo, integration_repo, tool_repo, audit, events)
    toolset = ToolsetResolver(lifecycle, integration_repo, tool_repo, setting_repo, binding_repo, adapters)
    end_users = EndUserService(lifecycle, end_user_repo, signer, audit, events, invocation_repo)
    principals = PrincipalResolver(end_users)
    approvals = ApprovalService(signer, end_users, audit)
    stages = build_stages(
        toolset, end_users, signer, shared.limiter, shared.breaker, shared.idempotency, credentials, adapters, health
    )
    gateway = ToolExecutionGateway(stages, InvocationRecorder(invocation_repo, audit))

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
    )


def get_tools_container(
    crypto: CryptoService = Depends(get_crypto_service),
    guard: OutboundUrlGuard = Depends(get_outbound_url_guard),
) -> ToolsContainer:
    """FastAPI dependency: the fully wired Module 07 services."""
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
    )


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
    )
