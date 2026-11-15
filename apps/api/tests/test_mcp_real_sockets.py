"""
MCP over real loopback sockets: the legacy HTTP+SSE transport (SRS-07 FR-20) and real ``list_changed`` delivery (FR-10).

An in-process ASGI transport cannot carry a long-lived SSE stream, so these tests run the official SDK server under
uvicorn and connect with the real connector through a guard that permits loopback and plain http (tests only).
"""
import asyncio
from typing import Any, Dict, List, Optional, Tuple

import pytest
from beanie import PydanticObjectId
from mcp.server.transport_security import TransportSecuritySettings

from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import UpstreamAuthError, UpstreamError
from app.core.tools.types import ResolvedCredentials
from app.integrations.adapters import McpAdapter
from app.integrations.mcp_client import SdkMcpConnector, should_fall_back_to_sse
from app.models.integration import Integration, IntegrationType
from tests.mcp_test_server import BearerGate, build_server
from tests.socket_server import serve

pytestmark = pytest.mark.usefixtures("tool_models")

SECURITY = TransportSecuritySettings(enable_dns_rebinding_protection=False)
NO_CREDS = ResolvedCredentials()


class Recorder:
    """ASGI wrapper recording (method, path) of every HTTP request, optionally refusing some paths with a status."""

    def __init__(self, app: Any, reject: Optional[Dict[str, int]] = None) -> None:
        self.app = app
        self.requests: List[Tuple[str, str]] = []
        self.reject = reject or {}

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            self.requests.append((scope["method"], scope["path"]))
            status = self.reject.get(scope["path"])
            if status:
                await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"refused"})
                return
        await self.app(scope, receive, send)


def streamable_app(announce: bool = False) -> Any:
    return build_server(announce=announce).streamable_http_app(transport_security=SECURITY)


def sse_app(announce: bool = False) -> Any:
    return build_server(announce=announce).sse_app(transport_security=SECURITY)


def connector(callback: Any = None) -> SdkMcpConnector:
    guard = OutboundUrlGuard(allow_private_networks=True, allow_insecure_http=True)
    return SdkMcpConnector(guard, on_list_changed=callback)


def integration(url: str, transport: str) -> Integration:
    return Integration(
        project_id=PydanticObjectId(), type=IntegrationType.MCP, slug="srv", name="Srv",
        config={"url": url, "transport": transport, "request_timeout_seconds": 10}, created_by="u", updated_by="u",
    )


async def list_names(conn: SdkMcpConnector, integ: Integration, creds: ResolvedCredentials = NO_CREDS) -> Tuple[List[str], str]:
    async with conn.connect(integ, creds) as session:
        return sorted(t["name"] for t in await session.list_tools()), session.transport  # type: ignore[attr-defined]


# ====================================================================== transports
async def test_streamable_http_works_over_a_real_socket():
    async with serve(streamable_app()) as base:
        names, transport = await list_names(connector(), integration(f"{base}/mcp", "streamable_http"))
    assert "echo" in names and transport == "streamable_http"


async def test_the_legacy_sse_transport_lists_and_calls_tools():
    async with serve(sse_app()) as base:
        conn, integ = connector(), integration(f"{base}/sse", "sse_legacy")
        async with conn.connect(integ, NO_CREDS) as session:
            assert session.transport == "sse_legacy"  # type: ignore[attr-defined]
            assert "echo" in {t["name"] for t in await session.list_tools()}
            result = await session.call_tool("echo", {"message": "hi"})
    assert "echo:hi" in str(result)


async def test_auto_falls_back_to_sse_when_streamable_http_is_refused_at_creation():
    recorder = Recorder(sse_app())
    async with serve(recorder) as base:
        names, transport = await list_names(connector(), integration(f"{base}/sse", "auto"))
    assert "echo" in names and transport == "sse_legacy"
    assert ("POST", "/sse") in recorder.requests and ("GET", "/sse") in recorder.requests  # tried streamable first


async def test_auto_stays_on_streamable_http_when_the_server_supports_it():
    recorder = Recorder(streamable_app())
    async with serve(recorder) as base:
        _, transport = await list_names(connector(), integration(f"{base}/mcp", "auto"))
    assert transport == "streamable_http" and all(path == "/mcp" for _, path in recorder.requests)


async def test_an_explicit_streamable_config_never_falls_back():
    recorder = Recorder(sse_app())
    async with serve(recorder) as base:
        with pytest.raises(UpstreamError):
            await list_names(connector(), integration(f"{base}/sse", "streamable_http"))
    assert ("GET", "/sse") not in recorder.requests


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
async def test_auto_does_not_fall_back_on_auth_rate_limit_or_server_errors(status):
    """A streamable POST answered with these statuses must surface as an error, never as a silent change of transport."""
    refuse = Recorder(streamable_app(), reject={"/mcp": status})
    async with serve(refuse) as base:
        with pytest.raises(UpstreamError):
            await list_names(connector(), integration(f"{base}/mcp", "auto"))
    assert refuse.requests and all(method == "POST" for method, _ in refuse.requests)  # no GET: SSE was never tried


async def test_credentials_reach_both_the_sse_stream_and_the_message_posts():
    gate = BearerGate(sse_app(), "s3cret")
    async with serve(gate) as base:
        good = ResolvedCredentials(headers={"Authorization": "Bearer s3cret"})
        names, transport = await list_names(connector(), integration(f"{base}/sse", "sse_legacy"), good)
        assert "echo" in names and transport == "sse_legacy"
        bad = ResolvedCredentials(headers={"Authorization": "Bearer wrong"})
        with pytest.raises(UpstreamAuthError):
            await list_names(connector(), integration(f"{base}/sse", "sse_legacy"), bad)


async def test_the_outbound_guard_still_governs_the_legacy_transport():
    async with serve(sse_app()) as base:
        strict = SdkMcpConnector(OutboundUrlGuard())  # default guard: no loopback, no plain http
        with pytest.raises(UpstreamError):
            await list_names(strict, integration(f"{base}/sse", "sse_legacy"))


def test_fallback_is_decided_only_by_the_statuses_a_legacy_server_returns():
    assert should_fall_back_to_sse([404]) and should_fall_back_to_sse([405]) and should_fall_back_to_sse([400])
    assert not should_fall_back_to_sse([]) and not should_fall_back_to_sse([200])
    assert not should_fall_back_to_sse([404, 401]) and not should_fall_back_to_sse([405, 500]) and not should_fall_back_to_sse([429])


async def test_the_adapter_reports_the_resolved_transport_in_the_probe():
    async with serve(sse_app()) as base:
        probe = await McpAdapter(connector()).probe(integration(f"{base}/sse", "auto"), NO_CREDS)
    assert probe.healthy and probe.server_info["transport"] == "sse_legacy"


# ====================================================================== real list_changed delivery
@pytest.mark.parametrize(
    "make_app,path,transport", [(streamable_app, "/mcp", "streamable_http"), (sse_app, "/sse", "sse_legacy")]
)
async def test_a_real_list_changed_notification_reaches_the_callback(make_app, path, transport):
    seen: List[str] = []
    arrived = asyncio.Event()

    async def callback(integ: Integration, kind: str) -> None:
        seen.append(kind)
        arrived.set()

    async with serve(make_app(announce=True)) as base:
        async with connector(callback).connect(integration(f"{base}{path}", transport), NO_CREDS) as session:
            await session.call_tool("announce_change", {})
            await asyncio.wait_for(arrived.wait(), timeout=10)
    assert seen == ["tools"]


def test_config_accepts_the_three_transports_and_rejects_anything_else():
    from app.core.exceptions import BadRequestError

    adapter = McpAdapter(connector())
    for transport in ("streamable_http", "sse_legacy", "auto"):
        assert adapter.validate_config({"url": "https://x.example/mcp", "transport": transport})["transport"] == transport
    assert adapter.validate_config({"url": "https://x.example/mcp"})["transport"] == "streamable_http"
    for bad in ("websocket", "sse", "", None):
        with pytest.raises(BadRequestError):
            adapter.validate_config({"url": "https://x.example/mcp", "transport": bad})
