"""
MCP connector built on the **official MCP Python SDK** (SRS-07 FR-18..20, R-5).

Only the MCP adapter references this module, through ``McpConnectorPort``. The SDK's
``ClientSession`` and Streamable HTTP transport are used as-is; the only customization is
the HTTP client, which sits on the ``GuardedAsyncTransport`` so the Outbound Guard governs
all traffic. SDK and transport exceptions are mapped to the neutral ``Upstream*`` errors.
"""
from __future__ import annotations

from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Protocol

import httpx2
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from app.core.exceptions import UrlBlockedError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import (
    UpstreamAuthError,
    UpstreamError,
    UpstreamRateLimited,
    UpstreamSessionExpired,
    UpstreamTargetBlocked,
    UpstreamTimeout,
)
from app.core.tools.types import ResolvedCredentials
from app.integrations.guarded_transport import GuardedAsyncTransport
from app.models.integration import Integration

CLIENT_NAME = "axion"
CLIENT_VERSION = "1.0.0"
MAX_TOOL_PAGES = 50
UI_EXTENSION = {"io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}}


class McpSessionPort(Protocol):
    server_info: Dict[str, Any]
    capabilities: Dict[str, Any]
    protocol_version: Optional[str]

    async def list_tools(self) -> List[Dict[str, Any]]: ...

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]: ...


class McpConnectorPort(Protocol):
    def connect(
        self, integration: Integration, credentials: ResolvedCredentials
    ) -> AbstractAsyncContextManager[McpSessionPort]:
        """Open an initialized session; closing the context terminates it."""
        ...


# --------------------------------------------------------------------------- error mapping
def _leaf_exceptions(exc: BaseException) -> List[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        leaves: List[BaseException] = []
        for inner in exc.exceptions:
            leaves.extend(_leaf_exceptions(inner))
        return leaves
    return [exc]


def _chain(exc: BaseException) -> List[BaseException]:
    seen: List[BaseException] = []
    current: Optional[BaseException] = exc
    while current is not None and current not in seen and len(seen) < 10:
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


def _status_error(status: int) -> UpstreamError:
    if status in (401, 403):
        return UpstreamAuthError("Upstream rejected the credentials")
    if status == 404:
        return UpstreamSessionExpired("MCP session expired")
    if status == 429:
        return UpstreamRateLimited("Upstream rate limit reached")
    return UpstreamError(f"Upstream returned HTTP {status}")


def map_sdk_exception(exc: BaseException, http_statuses: Optional[List[int]] = None) -> Exception:
    """
    Translate SDK/transport exceptions into neutral upstream errors.

    The SDK reports HTTP failures as a generic JSON-RPC error and drops the status, so the
    connector records response statuses with an HTTP hook and passes them here.
    """
    leaf = _leaf_exceptions(exc)[0]
    if isinstance(leaf, UpstreamError):
        return leaf
    chain = _chain(leaf)

    if any(isinstance(e, UrlBlockedError) for e in chain):
        return UpstreamTargetBlocked("The upstream target is not permitted")

    for candidate in chain:
        response = getattr(candidate, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int) and status >= 400:
            return _status_error(status)

    if any(isinstance(e, (TimeoutError, httpx2.TimeoutException)) for e in chain):
        return UpstreamTimeout("Upstream request timed out")
    failed = [s for s in (http_statuses or []) if s >= 400]
    if failed:
        return _status_error(failed[0])
    if isinstance(leaf, MCPError):
        return UpstreamError(f"MCP error {leaf.code}: {str(leaf.message)[:200]}")
    if any(isinstance(e, httpx2.HTTPError) for e in chain):
        return UpstreamError("Upstream connection failed")
    return UpstreamError(f"Upstream failure: {type(leaf).__name__}")


# ------------------------------------------------------------------------------ session
class SdkMcpSession:
    def __init__(self, session: ClientSession, init: types.InitializeResult, timeout: float) -> None:
        self._session = session
        self._timeout = timeout
        dumped = init.model_dump(by_alias=True, exclude_none=True)
        self.server_info: Dict[str, Any] = dumped.get("serverInfo") or {}
        self.capabilities: Dict[str, Any] = dumped.get("capabilities") or {}
        self.protocol_version: Optional[str] = dumped.get("protocolVersion")

    async def list_tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(MAX_TOOL_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await self._session.list_tools(params=params)
            tools.extend(t.model_dump(by_alias=True, exclude_none=True) for t in page.tools)
            cursor = page.next_cursor
            if not cursor:
                return tools
        raise UpstreamError("Upstream tool listing exceeded the pagination limit")

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        result = await self._session.call_tool(name, arguments, read_timeout_seconds=self._timeout)
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        if "content" not in dumped and "structuredContent" not in dumped:
            raise UpstreamError("The tool requested interactive input, which is not supported")
        return dumped


class SdkMcpConnector:
    """Default ``McpConnectorPort``: official SDK over Streamable HTTP, guarded."""

    def __init__(
        self,
        guard: OutboundUrlGuard,
        *,
        inner_transport: Optional[httpx2.AsyncBaseTransport] = None,
        pin_ips: bool = True,
    ) -> None:
        self._guard = guard
        self._inner = inner_transport
        self._pin = pin_ips

    @asynccontextmanager
    async def connect(
        self, integration: Integration, credentials: ResolvedCredentials
    ) -> AsyncIterator[McpSessionPort]:
        config = integration.config
        timeout = float(config.get("request_timeout_seconds", 30))
        transport = GuardedAsyncTransport(
            self._guard, allowed_hosts=config.get("allowed_hosts"), inner=self._inner, pin_ips=self._pin
        )
        statuses: List[int] = []

        async def record_status(response: httpx2.Response) -> None:
            statuses.append(response.status_code)

        client = httpx2.AsyncClient(
            event_hooks={"response": [record_status]},
            transport=transport,
            headers=credentials.headers or None,
            params=credentials.query or None,
            timeout=httpx2.Timeout(timeout),
            follow_redirects=False,
        )
        try:
            async with client:
                async with streamable_http_client(config["url"], http_client=client) as streams:
                    async with ClientSession(
                        streams[0],
                        streams[1],
                        read_timeout_seconds=timeout,
                        client_info=types.Implementation(name=CLIENT_NAME, version=CLIENT_VERSION),
                        extensions=UI_EXTENSION,
                    ) as session:
                        init = await session.initialize()
                        yield SdkMcpSession(session, init, timeout)
        except UpstreamError:
            raise
        except BaseException as exc:  # noqa: BLE001 - re-raised after mapping
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise map_sdk_exception(exc, statuses) from exc
