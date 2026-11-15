"""
In-process MCP server built with the **official SDK** for end-to-end adapter tests.

It is served through an ``httpx2.ASGITransport`` (no sockets, no network), optionally
behind a tiny ASGI wrapper that enforces a bearer token so authentication failures can
be exercised.
"""
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

import httpx2
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

HOST = "mcp.example.com"
URL = f"https://{HOST}/mcp"


APP_URI = "ui://charts/main"
APP_HTML_V1 = "<html><body><h1>chart v1</h1></body></html>"


def build_server(extras: bool = False, announce: bool = False) -> MCPServer:
    server = MCPServer("axion-test-server")
    server.app_state = {
        "html": APP_HTML_V1,
        "mime": "text/html;profile=mcp-app",
        "csp": {"connectDomains": ["https://api.charts.example"], "resourceDomains": ["https://cdn.charts.example"]},
        "permissions": {"geolocation": {}},
    }  # type: ignore[attr-defined]

    @server.tool(
        name="echo",
        description="Echo a message back.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def echo(message: str) -> str:
        return f"echo:{message}"

    @server.tool(
        name="delete_everything",
        description="Dangerous tool.",
        annotations=ToolAnnotations(destructive_hint=True, read_only_hint=False),
    )
    def delete_everything(confirm: bool = False) -> str:
        return "deleted" if confirm else "nothing"

    @server.tool(name="explode", description="Always fails.")
    def explode() -> str:
        raise ValueError("boom")

    @server.tool(
        name="show_chart",
        description="Tool that declares an MCP App.",
        meta={"ui": {"resourceUri": "ui://charts/main", "visibility": ["model", "app"]}},
    )
    def show_chart(series: str = "a") -> str:
        return f"chart:{series}"

    if announce:

        @server.tool(name="announce_change", description="Emit tools/list_changed to the connected client.")
        async def announce_change(ctx: Context) -> str:
            await ctx.session.send_tool_list_changed()
            return "announced"

    if extras:
        state = server.app_state  # type: ignore[attr-defined]

        @server.tool(
            name="refresh_chart",
            description="App-only tool: refresh the chart data.",
            annotations=ToolAnnotations(read_only_hint=True),
            meta={"ui": {"resourceUri": APP_URI, "visibility": ["app"]}},
        )
        def refresh_chart(series: str = "a") -> str:
            return f"refreshed:{series}"

        @server.resource(
            APP_URI, name="chart-ui", mime_type="text/html;profile=mcp-app",
            meta={"ui": {"csp": state["csp"], "permissions": state["permissions"]}},
        )
        def chart_ui() -> str:
            return state["html"]

        @server.resource("notes://readme", name="readme", mime_type="text/plain")
        def readme() -> str:
            return "hello from the server"

        @server.resource("docs://{name}", name="doc", mime_type="text/plain")
        def doc(name: str) -> str:
            return f"doc:{name}"

        @server.prompt()
        def summarize(text: str) -> str:
            return f"Summarize: {text}"

    return server


class BearerGate:
    """ASGI wrapper rejecting requests without the expected bearer token with 401."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token
        self.seen_hosts: list[str] = []

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            self.seen_hosts.append(headers.get("host", ""))
            if headers.get("authorization") != f"Bearer {self.token}":
                await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


@asynccontextmanager
async def running_transport(token: Optional[str] = None, extras: bool = False) -> AsyncIterator[tuple[httpx2.ASGITransport, Any]]:
    """Yield ``(transport, gate)`` for an in-process server; the lifespan runs the session manager."""
    server = build_server(extras=extras)
    app = server.streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    async with app.router.lifespan_context(app):
        wrapped: Any = BearerGate(app, token) if token else app
        wrapped.app_state = server.app_state  # tests mutate this to simulate the server changing its UI
        yield httpx2.ASGITransport(app=wrapped), wrapped
