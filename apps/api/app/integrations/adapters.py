"""
Integration adapters (SRS-07 Section 8): ``NativeAdapter`` and ``McpAdapter``.

Each implements only the role interfaces it supports. Adapters contain no authorization,
approval, subject, or audit logic: those belong to the Gateway stages and services.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from app.core.exceptions import BadRequestError
from app.core.tools.errors import UpstreamAuthError, UpstreamError, UpstreamRateLimited
from app.core.tools.types import (
    ContentBlock,
    DiscoveredTool,
    ProbeResult,
    RawToolResult,
    ResolvedCredentials,
    ResolvedTool,
)
from app.integrations.mcp_client import McpConnectorPort
from app.integrations.native import NativeProviderRegistry, require_provider
from app.models.integration import AuthType, Integration


# ----------------------------------------------------------------------------- native
class NativeAdapter:
    key = "native"

    def __init__(self, providers: NativeProviderRegistry) -> None:
        self._providers = providers

    # ConfigDescriptor
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        provider = require_provider(self._providers, config.get("provider_key"))
        return {"provider_key": provider.key}

    def supported_auth_types(self) -> Set[AuthType]:
        return {AuthType.NONE}

    def target_urls(self, config: Dict[str, Any]) -> List[str]:
        return []

    def allowed_hosts(self, config: Dict[str, Any]) -> Optional[List[str]]:
        return None

    # ToolDiscoverer
    async def discover(self, integration: Integration, credentials: ResolvedCredentials) -> List[DiscoveredTool]:
        provider = require_provider(self._providers, integration.config.get("provider_key"))
        return [spec.to_discovered() for spec in provider.tools]

    # ToolExecutor
    async def execute(
        self,
        integration: Integration,
        tool: ResolvedTool,
        arguments: Dict[str, Any],
        credentials: ResolvedCredentials,
        timeout_seconds: int,
    ) -> RawToolResult:
        provider = require_provider(self._providers, integration.config.get("provider_key"))
        spec = provider.tool(tool.upstream_name)
        if spec is None:
            raise UpstreamError(f"Native tool '{tool.upstream_name}' is no longer provided")
        return await spec.handler(arguments)

    # HealthProber
    async def probe(self, integration: Integration, credentials: ResolvedCredentials) -> ProbeResult:
        healthy = self._providers.get(str(integration.config.get("provider_key"))) is not None
        return ProbeResult(
            healthy=healthy,
            latency_ms=0,
            status="healthy" if healthy else "unreachable",
            message=None if healthy else "Native provider is not available",
        )


# --------------------------------------------------------------------------------- mcp
def _map_annotations(raw: Dict[str, Any]) -> Dict[str, Optional[bool]]:
    mapping = {
        "readOnlyHint": "read_only",
        "destructiveHint": "destructive",
        "idempotentHint": "idempotent",
        "openWorldHint": "open_world",
    }
    return {target: raw[source] for source, target in mapping.items() if isinstance(raw.get(source), bool)}


def _map_ui(meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ui = meta.get("ui") if isinstance(meta.get("ui"), dict) else {}
    uri = ui.get("resourceUri") or meta.get("ui/resourceUri")
    if not isinstance(uri, str) or not uri.startswith("ui://"):
        return None
    visibility = ui.get("visibility")
    if not (isinstance(visibility, list) and all(v in ("model", "app") for v in visibility) and visibility):
        visibility = ["model", "app"]
    return {"resource_uri": uri, "visibility": visibility}


def map_mcp_tool(raw: Dict[str, Any]) -> DiscoveredTool:
    schema = raw.get("inputSchema") if isinstance(raw.get("inputSchema"), dict) else None
    return DiscoveredTool(
        name=str(raw.get("name", "")),
        title=raw.get("title") if isinstance(raw.get("title"), str) else None,
        description=str(raw.get("description") or "")[:8000],
        input_schema=schema or {"type": "object", "properties": {}},
        output_schema=raw.get("outputSchema") if isinstance(raw.get("outputSchema"), dict) else None,
        annotations=_map_annotations(raw.get("annotations") or {}),
        ui=_map_ui(raw.get("_meta") or {}),
    )


def map_mcp_result(result: Dict[str, Any]) -> RawToolResult:
    blocks: List[ContentBlock] = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "text":
            blocks.append(ContentBlock(type="text", text=str(item.get("text", ""))))
        elif kind == "image":
            blocks.append(ContentBlock(type="image", data=item.get("data"), mime_type=item.get("mimeType")))
        elif kind == "resource_link":
            blocks.append(ContentBlock(type="resource_link", data={"uri": item.get("uri"), "name": item.get("name")}))
        elif kind == "resource":
            blocks.append(ContentBlock(type="data", data=item.get("resource")))
    is_error = bool(result.get("isError"))
    message = next((b.text for b in blocks if b.type == "text" and b.text), None) if is_error else None
    return RawToolResult(
        content=blocks,
        structured_content=result.get("structuredContent"),
        is_error=is_error,
        error_message=message,
    )


class McpAdapter:
    key = "mcp"

    def __init__(self, connector: McpConnectorPort) -> None:
        self._connector = connector

    # ConfigDescriptor
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        url = config.get("url")
        if not isinstance(url, str) or not url.strip():
            raise BadRequestError("MCP integrations require a 'url'")
        transport = config.get("transport", "streamable_http")
        if transport != "streamable_http":
            raise BadRequestError("Only the 'streamable_http' MCP transport is supported")
        timeout = config.get("request_timeout_seconds", 30)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 120:
            raise BadRequestError("request_timeout_seconds must be an integer between 1 and 120")
        allowed = config.get("allowed_hosts")
        if allowed is not None and (
            not isinstance(allowed, list) or not all(isinstance(h, str) and h for h in allowed)
        ):
            raise BadRequestError("allowed_hosts must be a list of host patterns")
        normalized: Dict[str, Any] = {"url": url.strip(), "transport": transport, "request_timeout_seconds": timeout}
        if allowed:
            normalized["allowed_hosts"] = allowed
        return normalized

    def supported_auth_types(self) -> Set[AuthType]:
        return {AuthType.NONE, AuthType.API_KEY, AuthType.BEARER, AuthType.BASIC, AuthType.CUSTOM_HEADERS}

    def target_urls(self, config: Dict[str, Any]) -> List[str]:
        return [config["url"]]

    def allowed_hosts(self, config: Dict[str, Any]) -> Optional[List[str]]:
        return config.get("allowed_hosts")

    # ToolDiscoverer
    async def discover(self, integration: Integration, credentials: ResolvedCredentials) -> List[DiscoveredTool]:
        async with self._connector.connect(integration, credentials) as session:
            return [map_mcp_tool(t) for t in await session.list_tools() if t.get("name")]

    # ToolExecutor
    async def execute(
        self,
        integration: Integration,
        tool: ResolvedTool,
        arguments: Dict[str, Any],
        credentials: ResolvedCredentials,
        timeout_seconds: int,
    ) -> RawToolResult:
        async with self._connector.connect(integration, credentials) as session:
            return map_mcp_result(await session.call_tool(tool.upstream_name, arguments))

    # HealthProber
    async def probe(self, integration: Integration, credentials: ResolvedCredentials) -> ProbeResult:
        start = time.monotonic()
        try:
            async with self._connector.connect(integration, credentials) as session:
                return ProbeResult(
                    healthy=True,
                    latency_ms=int((time.monotonic() - start) * 1000),
                    status="healthy",
                    server_info={
                        "server": session.server_info,
                        "protocol_version": session.protocol_version,
                        "capabilities": sorted(session.capabilities.keys()),
                    },
                )
        except UpstreamAuthError:
            return ProbeResult(healthy=False, status="auth_failed", message="Upstream rejected the credentials")
        except UpstreamRateLimited:
            return ProbeResult(healthy=False, status="rate_limited", message="Upstream rate limit reached")
        except UpstreamError as exc:
            return ProbeResult(healthy=False, status="unreachable", message=str(exc)[:300])
