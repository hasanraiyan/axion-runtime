"""
Test harness for Module 07: builds a fully wired ``ToolsContainer`` from in-memory fakes, plus a
scriptable adapter that doubles as proof of extensibility (a brand-new integration type is added
without touching any service, stage, or schema).
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from app.core.config import settings
from app.core.exceptions import BadRequestError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.events import InProcessEventBus
from app.core.tools.resilience import CircuitBreaker, IdempotencyStore, KeyedLocks, SlidingWindowRateLimiter
from app.core.tools.signing import TokenSigner
from app.core.tools.types import (
    Actor,
    ActorType,
    ContentBlock,
    DiscoveredTool,
    PrincipalContext,
    ProbeResult,
    RawToolResult,
    ResolvedCredentials,
    ResolvedTool,
    Subject,
    SubjectType,
)
from app.integrations.native import build_default_native_registry
from app.models.integration import AuthType, Integration
from app.models.project import Project
from app.services.tools.providers import SharedToolState, ToolsContainer, build_tools_container
from tests.fakes.tool_repositories import (
    FakeAppResourceRepository,
    FakeAuditRepository,
    FakeConnectionRepository,
    FakeConnectSessionRepository,
    FakeCrypto,
    FakeOAuthClientRepository,
    FakeToolPolicyRepository,
    FakeEndUserRepository,
    FakeIntegrationRepository,
    FakeProjectRepository,
    FakeSecretRepository,
    FakeToolBindingRepository,
    FakeToolDefinitionRepository,
    FakeToolInvocationRepository,
    FakeToolSettingRepository,
    make_project,
)


class StaticResolver:
    async def resolve(self, host: str, port: int) -> List[str]:
        return ["93.184.216.34"]


class ScriptedAdapter:
    """
    A complete adapter implementing every role, driven by in-memory state. Registered under
    ``custom:scripted`` it exercises the full stack for a type the platform has never heard of.
    """

    key = "custom:scripted"

    def __init__(self) -> None:
        self.catalog: List[DiscoveredTool] = []
        self.calls: List[Dict[str, Any]] = []
        self.handler: Callable[[str, Dict[str, Any]], RawToolResult] = lambda name, args: RawToolResult(
            content=[ContentBlock(type="text", text=f"{name}:{args}")]
        )
        self.raise_on_execute: Optional[BaseException] = None
        self.raise_on_discover: Optional[BaseException] = None
        self.probe_result = ProbeResult(healthy=True, latency_ms=1)
        self.probe_handler: Optional[Callable[[ResolvedCredentials], ProbeResult]] = None
        self.seen_credentials: List[ResolvedCredentials] = []
        self.sleep: float = 0.0
        self.discover_delay: float = 0.0

    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if config.get("kind") != "scripted":
            raise BadRequestError("bad kind")
        return {"kind": "scripted"}

    def supported_auth_types(self) -> Set[AuthType]:
        return {
            AuthType.NONE,
            AuthType.API_KEY,
            AuthType.BEARER,
            AuthType.CUSTOM_HEADERS,
            AuthType.BASIC,
            AuthType.OAUTH_AUTHORIZATION_CODE,
            AuthType.OAUTH_CLIENT_CREDENTIALS,
        }

    def target_urls(self, config: Dict[str, Any]) -> List[str]:
        return []

    def allowed_hosts(self, config: Dict[str, Any]) -> Optional[List[str]]:
        return None

    async def discover(self, integration: Integration, credentials: ResolvedCredentials) -> List[DiscoveredTool]:
        self.seen_credentials.append(credentials)
        if self.discover_delay:
            import asyncio

            await asyncio.sleep(self.discover_delay)
        if self.raise_on_discover:
            raise self.raise_on_discover
        return list(self.catalog)

    async def execute(self, integration: Integration, tool: ResolvedTool, arguments: Dict[str, Any], credentials: ResolvedCredentials, timeout_seconds: int) -> RawToolResult:
        import asyncio

        if tool.upstream_name not in {t.name for t in self.catalog}:
            from app.core.tools.errors import UpstreamError

            raise UpstreamError(f"unknown tool {tool.upstream_name}")
        self.calls.append({"tool": tool.upstream_name, "arguments": dict(arguments)})
        self.seen_credentials.append(credentials)
        if self.sleep:
            await asyncio.sleep(self.sleep)
        if self.raise_on_execute:
            raise self.raise_on_execute
        return self.handler(tool.upstream_name, arguments)

    async def probe(self, integration: Integration, credentials: ResolvedCredentials) -> ProbeResult:
        self.seen_credentials.append(credentials)
        if self.probe_handler is not None:
            return self.probe_handler(credentials)
        return self.probe_result


def tool(name: str, *, read_only: Optional[bool] = True, destructive: Optional[bool] = None, schema: Optional[Dict[str, Any]] = None, description: str = "", ui: Optional[Dict[str, Any]] = None) -> DiscoveredTool:
    annotations: Dict[str, Optional[bool]] = {}
    if read_only is not None:
        annotations["read_only"] = read_only
    if destructive is not None:
        annotations["destructive"] = destructive
    return DiscoveredTool(
        name=name,
        description=description or f"Tool {name}",
        input_schema=schema or {"type": "object", "properties": {"q": {"type": "string"}}, "additionalProperties": False},
        annotations=annotations,
        ui=ui,
    )


@dataclass
class Harness:
    container: ToolsContainer
    project: Project
    scripted: ScriptedAdapter
    projects: FakeProjectRepository
    secrets: FakeSecretRepository
    audit: FakeAuditRepository
    integrations: FakeIntegrationRepository
    tools_repo: FakeToolDefinitionRepository
    settings_repo: FakeToolSettingRepository
    bindings: FakeToolBindingRepository
    end_users: FakeEndUserRepository
    invocations: FakeToolInvocationRepository
    shared: SharedToolState
    connections_repo: FakeConnectionRepository
    sessions: FakeConnectSessionRepository
    oauth_clients: FakeOAuthClientRepository
    policies: FakeToolPolicyRepository
    app_repo: FakeAppResourceRepository
    clock: List[float] = field(default_factory=lambda: [0.0])

    @property
    def pid(self) -> str:
        return str(self.project.id)

    def principal(self, subject: Subject, *, agent_id: Optional[str] = None, origin: str = "runtime", member_role: Optional[str] = None) -> PrincipalContext:
        actor_type = ActorType.USER if subject.type == SubjectType.MEMBER else ActorType.MACHINE
        return PrincipalContext(
            project_id=self.pid,
            actor=Actor(actor_type, subject.id or "machine_1"),
            subject=subject,
            agent_id=agent_id,
            origin=origin,
            member_role=member_role,
        )


def make_harness(connector: Any = None, project: Optional[Project] = None, oauth: Any = None) -> Harness:
    projects = FakeProjectRepository()
    proj = projects.add(project or make_project())
    secrets, audit = FakeSecretRepository(), FakeAuditRepository()
    integrations, tools_repo, settings_repo = FakeIntegrationRepository(), FakeToolDefinitionRepository(), FakeToolSettingRepository()
    bindings, end_users, invocations = FakeToolBindingRepository(), FakeEndUserRepository(), FakeToolInvocationRepository()

    shared = SharedToolState(
        breaker=CircuitBreaker(),
        limiter=SlidingWindowRateLimiter(),
        idempotency=IdempotencyStore(),
        events=InProcessEventBus(),
        native=build_default_native_registry(),
        locks=KeyedLocks(),
    )
    conn_repo, sessions, oauth_clients, policies = FakeConnectionRepository(), FakeConnectSessionRepository(), FakeOAuthClientRepository(), FakeToolPolicyRepository()
    app_repo = FakeAppResourceRepository()
    container = build_tools_container(
        project_repo=projects,
        secret_repo=secrets,
        audit_repo=audit,
        crypto=FakeCrypto(),  # type: ignore[arg-type]
        integration_repo=integrations,
        tool_repo=tools_repo,
        setting_repo=settings_repo,
        binding_repo=bindings,
        end_user_repo=end_users,
        invocation_repo=invocations,
        guard=OutboundUrlGuard(StaticResolver()),
        shared=shared,
        signer=TokenSigner(settings.AXION_MASTER_ENCRYPTION_KEY),
        connector=connector,
        connection_repo=conn_repo,
        session_repo=sessions,
        oauth_client_repo=oauth_clients,
        policy_repo=policies,
        app_repo=app_repo,
        oauth=oauth,
        public_base_url="https://api.axion.test",
    )
    scripted = ScriptedAdapter()
    container.adapters.register(scripted)
    return Harness(
        container, proj, scripted, projects, secrets, audit, integrations, tools_repo, settings_repo, bindings, end_users,
        invocations, shared, conn_repo, sessions, oauth_clients, policies, app_repo,
    )
