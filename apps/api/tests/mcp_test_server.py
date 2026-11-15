"""
In-process MCP server built with the **official SDK** for end-to-end adapter tests.

It is served through an ``httpx2.ASGITransport`` (no sockets, no network), optionally
behind a tiny ASGI wrapper that enforces a bearer token so authentication failures can
be exercised.
"""
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

import httpx2
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

HOST = "mcp.example.com"
URL = f"https://{HOST}/mcp"


def build_server() -> MCPServer:
    server = MCPServer("axion-test-server")

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
async def running_transport(token: Optional[str] = None) -> AsyncIterator[tuple[httpx2.ASGITransport, Any]]:
    """Yield ``(transport, gate)`` for an in-process server; the lifespan runs the session manager."""
    server = build_server()
    app = server.streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    async with app.router.lifespan_context(app):
        wrapped: Any = BearerGate(app, token) if token else app
        yield httpx2.ASGITransport(app=wrapped), wrapped
