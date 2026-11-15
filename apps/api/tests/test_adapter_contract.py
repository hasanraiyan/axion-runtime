"""
Adapter contract suite (SRS-07 Section 10.8, Liskov Substitution).

Every integration adapter must behave identically at the contract level: same role
interfaces, the same error taxonomy, no extra preconditions. A new adapter is not mergeable
until it passes this suite. Runs against the native adapter, a scripted adapter, and the MCP
adapter talking to a real official-SDK server.
"""
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Tuple

import pytest
from beanie import PydanticObjectId

from app.core.exceptions import BadRequestError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import UpstreamError
from app.core.tools.ports import ConfigDescriptor, HealthProber, ToolDiscoverer, ToolExecutor, supports
from app.core.tools.types import DiscoveredTool, ProbeResult, RawToolResult, ResolvedCredentials, ResolvedTool
from app.integrations.adapters import McpAdapter, NativeAdapter
from app.integrations.mcp_client import SdkMcpConnector
from app.integrations.native import build_default_native_registry
from app.models.integration import AuthType, Integration, IntegrationType
from tests.mcp_test_server import URL, running_transport
from tests.tools_harness import ScriptedAdapter, StaticResolver, tool

pytestmark = pytest.mark.usefixtures("tool_models")

Case = Tuple[Any, Integration, str, Dict[str, Any]]


def _integration(kind: IntegrationType, config: Dict[str, Any]) -> Integration:
    return Integration(project_id=PydanticObjectId(), type=kind, slug="svc", name="Svc", config=config, created_by="u", updated_by="u")


def _resolved(name: str, schema: Dict[str, Any] | None = None) -> ResolvedTool:
    return ResolvedTool(
        tool_key=f"svc.{name}", integration_id="i", integration_slug="svc", integration_type="x", upstream_name=name,
        description="", input_schema=schema or {"type": "object"}, annotations={}, approval_policy="auto", timeout_seconds=10,
    )


class CaseFactory:
    """Opens the adapter under test. The MCP server's lifetime is scoped to one test body because
    its task group must be entered and exited in the same task (an anyio rule)."""

    def __init__(self, kind: str) -> None:
        self.kind = kind

    @asynccontextmanager
    async def open(self) -> AsyncIterator[Case]:
        if self.kind == "native":
            adapter = NativeAdapter(build_default_native_registry())
            yield adapter, _integration(IntegrationType.NATIVE, {"provider_key": "core_utils"}), "text_stats", {"text": "a b c"}
        elif self.kind == "scripted":
            adapter = ScriptedAdapter()
            adapter.catalog = [tool("known")]
            yield adapter, _integration(IntegrationType.CUSTOM, {"kind": "scripted"}), "known", {"q": "x"}
        else:
            async with running_transport() as (transport, _):
                adapter = McpAdapter(SdkMcpConnector(OutboundUrlGuard(StaticResolver()), inner_transport=transport))
                config = {"url": URL, "transport": "streamable_http", "request_timeout_seconds": 10}
                yield adapter, _integration(IntegrationType.MCP, config), "echo", {"message": "hi"}


@pytest.fixture(params=["native", "scripted", "mcp"])
def case(request) -> CaseFactory:
    return CaseFactory(request.param)


async def test_implements_the_required_roles(case):
    async with case.open() as (adapter, *_):
        assert isinstance(adapter, ConfigDescriptor) and supports(adapter, ToolExecutor)
        assert supports(adapter, ToolDiscoverer) and supports(adapter, HealthProber)
        assert adapter.key and isinstance(adapter.key, str)


async def test_config_validation_is_strict_and_normalizing(case):
    async with case.open() as (adapter, integration, *_):
        normalized = adapter.validate_config(dict(integration.config))
        assert isinstance(normalized, dict) and normalized
        assert adapter.validate_config(dict(normalized)) == normalized  # idempotent
        with pytest.raises(BadRequestError):
            adapter.validate_config({})
        with pytest.raises(BadRequestError):
            adapter.validate_config({"provider_key": 123, "url": 5, "kind": None})


async def test_declares_auth_types_urls_and_hosts_consistently(case):
    async with case.open() as (adapter, integration, *_):
        types = adapter.supported_auth_types()
        assert isinstance(types, set) and AuthType.NONE in types
        config = adapter.validate_config(dict(integration.config))
        urls = adapter.target_urls(config)
        assert isinstance(urls, list) and all(isinstance(u, str) for u in urls)
        hosts = adapter.allowed_hosts(config)
        assert hosts is None or isinstance(hosts, list)


async def test_discovery_returns_well_formed_unique_tools_and_does_not_mutate_state(case):
    async with case.open() as (adapter, integration, known, _):
        first = await adapter.discover(integration, ResolvedCredentials())
        second = await adapter.discover(integration, ResolvedCredentials())
        assert first and all(isinstance(t, DiscoveredTool) for t in first)
        names = [t.name for t in first]
        assert len(names) == len(set(names)) and known in names
        assert all(isinstance(t.input_schema, dict) and t.input_schema.get("type") == "object" for t in first)
        assert [t.name for t in second] == names  # discovery is repeatable and side-effect free


async def test_execute_returns_a_raw_result_for_a_known_tool(case):
    async with case.open() as (adapter, integration, known, args):
        result = await adapter.execute(integration, _resolved(known), args, ResolvedCredentials(), timeout_seconds=10)
        assert isinstance(result, RawToolResult) and not result.is_error


async def test_unknown_tool_fails_with_the_neutral_error_taxonomy(case):
    async with case.open() as (adapter, integration, *_):
        try:
            result = await adapter.execute(integration, _resolved("definitely_not_a_tool"), {}, ResolvedCredentials(), timeout_seconds=10)
        except UpstreamError:
            return  # contract option 1: a neutral upstream error
        assert isinstance(result, RawToolResult) and result.is_error  # contract option 2: an error result


async def test_execute_never_leaks_provider_specific_exceptions(case):
    async with case.open() as (adapter, integration, known, _):
        try:
            await adapter.execute(integration, _resolved(known), {"completely": "wrong", "shape": [1]}, ResolvedCredentials(), timeout_seconds=10)
        except UpstreamError:
            pass  # acceptable
        except Exception as exc:  # pragma: no cover - the contract violation we are guarding against
            pytest.fail(f"adapter leaked {type(exc).__name__}: callers must only ever see UpstreamError")


async def test_probe_reports_a_typed_result(case):
    async with case.open() as (adapter, integration, *_):
        probe = await adapter.probe(integration, ResolvedCredentials())
        assert isinstance(probe, ProbeResult) and probe.healthy and probe.status == "healthy"
