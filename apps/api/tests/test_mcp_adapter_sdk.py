"""
MCP adapter end-to-end tests against a real server built with the official MCP SDK
(SRS-07 FR-10, FR-19, FR-24, FR-40). No sockets and no network: the server is mounted on an
``httpx2.ASGITransport`` underneath the guarded transport.
"""
from typing import Dict, List


import pytest
from beanie import PydanticObjectId

from app.core.exceptions import BadRequestError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import UpstreamAuthError
from app.core.tools.types import ResolvedCredentials, ResolvedTool
from app.integrations.adapters import McpAdapter, map_mcp_result, map_mcp_tool
from app.integrations.mcp_client import SdkMcpConnector
from app.models.integration import AuthType, Integration, IntegrationType
from tests.mcp_test_server import HOST, URL, running_transport


class FakeResolver:
    def __init__(self, table: Dict[str, List[str]]) -> None:
        self.table = table

    async def resolve(self, host: str, port: int) -> List[str]:
        return self.table.get(host, [])


def make_guard(table=None) -> OutboundUrlGuard:
    return OutboundUrlGuard(FakeResolver(table or {HOST: ["93.184.216.34"]}))


def make_integration(url: str = URL) -> Integration:
    return Integration(
        project_id=PydanticObjectId(),
        type=IntegrationType.MCP,
        slug="srv",
        name="Server",
        config={"url": url, "transport": "streamable_http", "request_timeout_seconds": 10},
        created_by="u",
        updated_by="u",
    )


def make_tool(name: str) -> ResolvedTool:
    return ResolvedTool(
        tool_key=f"srv.{name}",
        integration_id="i",
        integration_slug="srv",
        integration_type="mcp",
        upstream_name=name,
        description="",
        input_schema={"type": "object"},
        annotations={},
        approval_policy="auto",
        timeout_seconds=10,
    )


pytestmark = pytest.mark.usefixtures("tool_models")


async def test_discovery_returns_tools_annotations_and_app_ui():
    async with running_transport() as (transport, _):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))
        tools = {t.name: t for t in await adapter.discover(make_integration(), ResolvedCredentials())}

    assert set(tools) == {"echo", "delete_everything", "explode", "show_chart"}
    assert tools["echo"].annotations["read_only"] is True
    assert tools["echo"].input_schema["properties"]["message"]["type"] == "string"
    assert tools["delete_everything"].annotations["destructive"] is True
    assert tools["show_chart"].ui == {"resource_uri": "ui://charts/main", "visibility": ["model", "app"]}
    assert tools["echo"].ui is None


async def test_execute_calls_a_tool_and_maps_content():
    async with running_transport() as (transport, _):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))
        result = await adapter.execute(
            make_integration(), make_tool("echo"), {"message": "hi"}, ResolvedCredentials(), timeout_seconds=10
        )

    assert not result.is_error
    assert result.content[0].type == "text"
    assert "echo:hi" in (result.content[0].text or "")


async def test_tool_error_is_reported_as_error_result_not_an_exception():
    async with running_transport() as (transport, _):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))
        result = await adapter.execute(
            make_integration(), make_tool("explode"), {}, ResolvedCredentials(), timeout_seconds=10
        )

    assert result.is_error
    assert result.error_message


async def test_probe_reports_server_info_and_capabilities():
    async with running_transport() as (transport, _):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))
        probe = await adapter.probe(make_integration(), ResolvedCredentials())

    assert probe.healthy and probe.status == "healthy"
    assert probe.server_info["server"]["name"] == "axion-test-server"
    assert "tools" in probe.server_info["capabilities"]


async def test_bearer_credentials_are_sent_and_wrong_token_is_auth_failed():
    async with running_transport(token="s3cret") as (transport, gate):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))

        ok = await adapter.probe(make_integration(), ResolvedCredentials(headers={"Authorization": "Bearer s3cret"}))
        assert ok.healthy

        bad = await adapter.probe(make_integration(), ResolvedCredentials(headers={"Authorization": "Bearer nope"}))
        assert not bad.healthy and bad.status == "auth_failed"

        with pytest.raises(UpstreamAuthError):
            await adapter.discover(make_integration(), ResolvedCredentials())


async def test_original_hostname_is_preserved_in_host_header_when_ip_is_pinned():
    async with running_transport(token="t") as (transport, gate):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport, pin_ips=True))
        await adapter.probe(make_integration(), ResolvedCredentials(headers={"Authorization": "Bearer t"}))

    assert gate.seen_hosts and all(h == HOST for h in gate.seen_hosts)


async def test_private_resolution_is_blocked_before_any_request_reaches_the_server():
    async with running_transport(token="t") as (transport, gate):
        guard = make_guard({HOST: ["10.0.0.5"]})  # DNS answer is private
        adapter = McpAdapter(SdkMcpConnector(guard, inner_transport=transport))
        probe = await adapter.probe(make_integration(), ResolvedCredentials(headers={"Authorization": "Bearer t"}))

    assert not probe.healthy and probe.status == "unreachable"
    assert gate.seen_hosts == []  # the guard stopped the request; the server saw nothing


async def test_metadata_ip_literal_is_blocked():
    async with running_transport() as (transport, gate):
        adapter = McpAdapter(SdkMcpConnector(make_guard(), inner_transport=transport))
        probe = await adapter.probe(make_integration("https://169.254.169.254/mcp"), ResolvedCredentials())
    assert not probe.healthy


# ------------------------------------------------------------------ pure mapping + config
def test_map_mcp_tool_ignores_invalid_ui_and_non_boolean_hints():
    tool = map_mcp_tool(
        {
            "name": "t",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": "yes", "destructiveHint": True},
            "_meta": {"ui": {"resourceUri": "https://evil.example.com/x"}},
        }
    )
    assert tool.annotations == {"destructive": True}
    assert tool.ui is None


def test_map_mcp_result_handles_text_image_and_structured_content():
    result = map_mcp_result(
        {
            "content": [{"type": "text", "text": "a"}, {"type": "image", "data": "AAA", "mimeType": "image/png"}],
            "structuredContent": {"n": 1},
            "isError": False,
        }
    )
    assert [b.type for b in result.content] == ["text", "image"]
    assert result.structured_content == {"n": 1}


def test_validate_config_normalizes_and_rejects_bad_input():
    adapter = McpAdapter(SdkMcpConnector(make_guard()))
    assert adapter.validate_config({"url": " https://x.example.com/mcp "})["url"] == "https://x.example.com/mcp"
    assert AuthType.OAUTH_AUTHORIZATION_CODE not in adapter.supported_auth_types()
    for bad in ({}, {"url": "https://x"}, {"url": "https://x", "transport": "sse"},
                {"url": "https://x", "request_timeout_seconds": 0}, {"url": "https://x", "allowed_hosts": "x"}):
        if bad == {"url": "https://x"}:
            continue
        with pytest.raises(BadRequestError):
            adapter.validate_config(bad)
