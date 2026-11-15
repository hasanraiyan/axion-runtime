"""
MCP connector built on the **official MCP Python SDK** (SRS-07 FR-18..20, R-5).

Only the MCP adapter references this module, through ``McpConnectorPort``. The SDK's
``ClientSession`` and Streamable HTTP transport are used as-is; the only customization is
the HTTP client, which sits on the ``GuardedAsyncTransport`` so the Outbound Guard governs
all traffic. SDK and transport exceptions are mapped to the neutral ``Upstream*`` errors.
"""
from __future__ import annotations

import logging
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Protocol

import httpx2
from mcp import ClientSession, types
from mcp.client.sse import sse_client
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

logger = logging.getLogger(__name__)

LIST_CHANGED_KINDS = {
    types.ToolListChangedNotification: "tools",
    types.ResourceListChangedNotification: "resources",
    types.PromptListChangedNotification: "prompts",
}
ListChangedCallback = Callable[[Integration, str], Awaitable[None]]
CLIENT_NAME = "axion"
CLIENT_VERSION = "1.0.0"
MAX_TOOL_PAGES = 50
UI_EXTENSION = {"io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}}


class McpSessionPort(Protocol):
    server_info: Dict[str, Any]
    transport: str
    capabilities: Dict[str, Any]
    protocol_version: Optional[str]

    async def list_tools(self) -> List[Dict[str, Any]]: ...

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]: ...

    async def list_resources(self) -> List[Dict[str, Any]]: ...

    async def list_resource_templates(self) -> List[Dict[str, Any]]: ...

    async def read_resource(self, uri: str) -> Dict[str, Any]: ...

    async def list_prompts(self) -> List[Dict[str, Any]]: ...


class McpConnectorPort(Protocol):
    def connect(
        self, integration: Integration, credentials: ResolvedCredentials
    ) -> AbstractAsyncContextManager[McpSessionPort]:
        """Open an initialized session; closing the context terminates it."""
        ...


def build_message_handler(integration: Integration, callback: Optional[ListChangedCallback]) -> Callable[[Any], Awaitable[None]]:
    """
    ClientSession message handler: forwards ``*/list_changed`` notifications and ignores everything else.
    A failing callback can never break the MCP session that delivered the notification.
    """

    async def on_message(message: Any) -> None:
        kind = LIST_CHANGED_KINDS.get(type(message))
        if kind is not None and callback is not None:
            try:
                await callback(integration, kind)
            except Exception:
                logger.exception("list_changed handler failed")

    return on_message


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
    def __init__(
        self,
        session: ClientSession,
        init: types.InitializeResult,
        timeout: float,
        http_statuses: Optional[List[int]] = None,
        transport: str = "streamable_http",
    ) -> None:
        self._session = session
        self.transport = transport  # the transport actually used, after any creation-time fallback
        self._timeout = timeout
        # HTTP statuses seen on this session's connection; the pool uses them to classify failures the SDK hides.
        self.http_statuses: List[int] = http_statuses if http_statuses is not None else []
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

    async def _paged(self, fetch: Any, attribute: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(MAX_TOOL_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await fetch(params=params)
            items.extend(i.model_dump(by_alias=True, exclude_none=True) for i in getattr(page, attribute))
            cursor = page.next_cursor
            if not cursor:
                return items
        raise UpstreamError("Upstream listing exceeded the pagination limit")

    async def list_resources(self) -> List[Dict[str, Any]]:
        return await self._paged(self._session.list_resources, "resources")

    async def list_resource_templates(self) -> List[Dict[str, Any]]:
        return await self._paged(self._session.list_resource_templates, "resource_templates")

    async def list_prompts(self) -> List[Dict[str, Any]]:
        return await self._paged(self._session.list_prompts, "prompts")

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        result = await self._session.read_resource(uri)
        contents = getattr(result, "contents", None)
        if not contents:
            raise UpstreamError("The resource returned no content")
        return contents[0].model_dump(by_alias=True, exclude_none=True)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        result = await self._session.call_tool(name, arguments, read_timeout_seconds=self._timeout)
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        if "content" not in dumped and "structuredContent" not in dumped:
            raise UpstreamError("The tool requested interactive input, which is not supported")
        return dumped


TRANSPORT_STREAMABLE = "streamable_http"
TRANSPORT_SSE_LEGACY = "sse_legacy"
TRANSPORT_AUTO = "auto"
SUPPORTED_TRANSPORTS = (TRANSPORT_STREAMABLE, TRANSPORT_SSE_LEGACY, TRANSPORT_AUTO)
# Statuses a server that only speaks the legacy HTTP+SSE transport returns to a Streamable HTTP POST (MCP spec,
# "Backwards compatibility"). Auth, rate-limit, and server errors are never a reason to try another transport.
SSE_FALLBACK_STATUSES = frozenset({400, 404, 405})


def should_fall_back_to_sse(statuses: List[int]) -> bool:
    refused = any(code in SSE_FALLBACK_STATUSES for code in statuses)
    return refused and not any(code in (401, 403, 429) or code >= 500 for code in statuses)


class SdkMcpConnector:
    """
    Default ``McpConnectorPort``: official SDK over Streamable HTTP, or the legacy HTTP+SSE transport, guarded.

    ``transport`` is ``streamable_http`` (default), ``sse_legacy``, or ``auto``. ``auto`` tries Streamable HTTP and falls
    back to SSE **only while the connection is being created** and only for the statuses a legacy server returns; once a
    session exists it is never switched. The transport actually used is exposed as ``session.transport``.
    """

    def __init__(
        self,
        guard: OutboundUrlGuard,
        *,
        inner_transport: Optional[httpx2.AsyncBaseTransport] = None,
        pin_ips: bool = True,
        on_list_changed: Optional[ListChangedCallback] = None,
    ) -> None:
        self._guard = guard
        self._inner = inner_transport
        self._pin = pin_ips
        self._on_list_changed = on_list_changed

    def _client(
        self,
        integration: Integration,
        credentials: ResolvedCredentials,
        statuses: List[int],
        timeout: httpx2.Timeout,
        headers: Optional[Dict[str, Any]] = None,
    ) -> httpx2.AsyncClient:
        config = integration.config
        transport = GuardedAsyncTransport(
            self._guard, allowed_hosts=config.get("allowed_hosts"), inner=self._inner, pin_ips=self._pin
        )

        async def record_status(response: httpx2.Response) -> None:
            statuses.append(response.status_code)

        merged = {**(credentials.headers or {}), **(headers or {})}
        return httpx2.AsyncClient(
            event_hooks={"response": [record_status]},
            transport=transport,
            headers=merged or None,
            params=credentials.query or None,
            timeout=timeout,
            follow_redirects=False,
        )

    @asynccontextmanager
    async def _open(
        self, integration: Integration, credentials: ResolvedCredentials, transport_name: str, statuses: List[int]
    ) -> AsyncIterator[SdkMcpSession]:
        config = integration.config
        timeout = float(config.get("request_timeout_seconds", 30))
        on_message = build_message_handler(integration, self._on_list_changed)

        @asynccontextmanager
        async def streams_for() -> AsyncIterator[Any]:
            if transport_name == TRANSPORT_SSE_LEGACY:

                def factory(
                    headers: Optional[Dict[str, Any]] = None, timeout: Optional[httpx2.Timeout] = None, auth: Any = None
                ) -> httpx2.AsyncClient:
                    return self._client(integration, credentials, statuses, timeout or httpx2.Timeout(30.0), headers)

                async with sse_client(config["url"], timeout=timeout, httpx_client_factory=factory) as streams:
                    yield streams
            else:
                client = self._client(integration, credentials, statuses, httpx2.Timeout(timeout))
                async with client:
                    async with streamable_http_client(config["url"], http_client=client) as streams:
                        yield streams

        async with streams_for() as streams:
            async with ClientSession(
                streams[0],
                streams[1],
                read_timeout_seconds=timeout,
                client_info=types.Implementation(name=CLIENT_NAME, version=CLIENT_VERSION),
                extensions=UI_EXTENSION,
                message_handler=on_message,
            ) as session:
                init = await session.initialize()
                yield SdkMcpSession(session, init, timeout, statuses, transport=transport_name)

    @asynccontextmanager
    async def connect(
        self, integration: Integration, credentials: ResolvedCredentials
    ) -> AsyncIterator[McpSessionPort]:
        configured = integration.config.get("transport", TRANSPORT_STREAMABLE)
        first = TRANSPORT_SSE_LEGACY if configured == TRANSPORT_SSE_LEGACY else TRANSPORT_STREAMABLE
        statuses: List[int] = []
        try:
            async with AsyncExitStack() as stack:
                try:
                    session = await stack.enter_async_context(self._open(integration, credentials, first, statuses))
                except BaseException as exc:  # noqa: BLE001
                    if (
                        configured != TRANSPORT_AUTO
                        or isinstance(exc, (KeyboardInterrupt, SystemExit))
                        or not should_fall_back_to_sse(statuses)
                    ):
                        raise
                    logger.info("Streamable HTTP was refused (%s); falling back to legacy SSE for this connection", statuses)
                    statuses = []
                    session = await stack.enter_async_context(
                        self._open(integration, credentials, TRANSPORT_SSE_LEGACY, statuses)
                    )
                yield session
        except UpstreamError:
            raise
        except BaseException as exc:  # noqa: BLE001 - re-raised after mapping
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise map_sdk_exception(exc, statuses) from exc
