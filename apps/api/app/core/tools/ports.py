"""
Ports and role interfaces for Module 07 (SRS-07 Sections 8 and 10.8).

Interface Segregation: an adapter implements only the roles it supports and callers
discover support with ``supports(adapter, Role)`` rather than calling stubs.
Dependency Inversion: services depend on these abstractions; concretes are wired
only in dependency providers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, Set, runtime_checkable

from app.core.tools.types import (
    DiscoveredTool,
    InvocationRequest,
    InvocationResult,
    PrincipalContext,
    ProbeResult,
    RawToolResult,
    ResolvedCredentials,
    ResolvedTool,
    Subject,
)
from app.models.integration import AuthProfile, AuthType, Integration

# ----------------------------------------------------------------------------
# Adapter role interfaces
# ----------------------------------------------------------------------------


@runtime_checkable
class ConfigDescriptor(Protocol):
    """Owns and validates an integration type's config; services treat config as opaque."""

    key: str

    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Return the normalized config or raise ``BadRequestError``."""
        ...

    def supported_auth_types(self) -> Set[AuthType]: ...

    def target_urls(self, config: Dict[str, Any]) -> List[str]:
        """Every outbound URL the config points at (validated by the Outbound Guard)."""
        ...

    def allowed_hosts(self, config: Dict[str, Any]) -> Optional[List[str]]: ...


@runtime_checkable
class ToolExecutor(Protocol):
    async def execute(
        self,
        integration: Integration,
        tool: ResolvedTool,
        arguments: Dict[str, Any],
        credentials: ResolvedCredentials,
        timeout_seconds: int,
    ) -> RawToolResult: ...


@runtime_checkable
class ToolDiscoverer(Protocol):
    async def discover(
        self, integration: Integration, credentials: ResolvedCredentials
    ) -> List[DiscoveredTool]: ...


@runtime_checkable
class HealthProber(Protocol):
    async def probe(self, integration: Integration, credentials: ResolvedCredentials) -> ProbeResult: ...


def supports(adapter: Any, role: type) -> bool:
    """Capability lookup (Liskov/ISP): does this adapter implement ``role``?"""
    return isinstance(adapter, role)


# ----------------------------------------------------------------------------
# Auth strategy (Open/Closed: one class per auth type, selected via a registry)
# ----------------------------------------------------------------------------


class SecretReaderPort(Protocol):
    async def read(self, project_id: str, secret_id: str) -> str:
        """Decrypt one MOD-02 secret into memory."""
        ...

    async def read_by_name(self, project_id: str, name: str) -> Optional[str]: ...


@runtime_checkable
class AuthStrategy(Protocol):
    auth_type: AuthType

    def validate(self, profile: AuthProfile) -> None:
        """Raise ``BadRequestError`` if the profile is malformed for this auth type."""
        ...

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        """MOD-02 secrets this profile references (for existence and deletion guards)."""
        ...

    def secret_names(self, profile: AuthProfile) -> List[str]:
        """MOD-02 secret *names* referenced through ``{{secrets.NAME}}`` templates."""
        ...

    async def build(
        self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort
    ) -> ResolvedCredentials: ...


class CredentialResolverPort(Protocol):
    """Resolve credentials for ``(integration, subject)``. There is no any-subject overload (FR-75)."""

    async def resolve(self, integration: Integration, subject: Subject) -> ResolvedCredentials: ...


# ----------------------------------------------------------------------------
# Infrastructure ports
# ----------------------------------------------------------------------------


class AuditPort(Protocol):
    async def record(self, project_id: str, actor_id: str, action: str, payload: Dict[str, Any]) -> None: ...


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class DomainEventPort(Protocol):
    async def publish(self, event: Any) -> None: ...


class ToolCatalogPort(Protocol):
    """What the runtime depends on to learn which tools a principal may use."""

    async def resolve_toolset(
        self, principal: PrincipalContext, agent_id: Optional[str] = None
    ) -> Any: ...


class ToolExecutionPort(Protocol):
    """What the runtime depends on to run a tool."""

    async def invoke(self, request: InvocationRequest) -> InvocationResult: ...
