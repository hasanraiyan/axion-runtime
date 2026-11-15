"""
Native tool catalog (SRS-07 5.7): Axion-implemented tools declared in code. A project
enables a native provider as an ``Integration`` of type ``native``; its tools are
materialized through the same discovery path as remote tools.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core.exceptions import BadRequestError
from app.core.tools.types import ContentBlock, DiscoveredTool, RawToolResult

NativeHandler = Callable[[Dict[str, Any]], Awaitable[RawToolResult]]


@dataclass(frozen=True)
class NativeToolSpec:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: NativeHandler
    annotations: Dict[str, Optional[bool]] = field(default_factory=dict)
    title: Optional[str] = None
    default_enabled: bool = False

    def to_discovered(self) -> DiscoveredTool:
        return DiscoveredTool(
            name=self.name,
            title=self.title,
            description=self.description,
            input_schema=self.input_schema,
            annotations=dict(self.annotations),
            default_enabled=self.default_enabled,
        )


@dataclass(frozen=True)
class NativeProvider:
    key: str
    name: str
    description: str
    tools: List[NativeToolSpec]

    def tool(self, name: str) -> Optional[NativeToolSpec]:
        return next((t for t in self.tools if t.name == name), None)


class NativeProviderRegistry:
    def __init__(self) -> None:
        self._providers: Dict[str, NativeProvider] = {}

    def register(self, provider: NativeProvider) -> None:
        if provider.key in self._providers:
            raise ValueError(f"Native provider '{provider.key}' already registered")
        self._providers[provider.key] = provider

    def get(self, key: str) -> Optional[NativeProvider]:
        return self._providers.get(key)

    def all(self) -> List[NativeProvider]:
        return sorted(self._providers.values(), key=lambda p: p.key)


# ------------------------------------------------------------------ core_utils provider
async def _current_time(arguments: Dict[str, Any]) -> RawToolResult:
    tz_name = arguments.get("timezone") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        return RawToolResult(is_error=True, error_message=f"Unknown timezone '{str(tz_name)[:60]}'")
    now = datetime.now(timezone.utc).astimezone(tz)
    payload = {"iso": now.isoformat(), "timezone": tz_name, "unix": int(now.timestamp())}
    return RawToolResult(content=[ContentBlock(type="text", text=now.isoformat())], structured_content=payload)


async def _text_stats(arguments: Dict[str, Any]) -> RawToolResult:
    text = str(arguments.get("text", ""))
    words = re.findall(r"\S+", text)
    payload = {"characters": len(text), "words": len(words), "lines": len(text.splitlines()) or (1 if text else 0)}
    return RawToolResult(
        content=[ContentBlock(type="text", text=f"{payload['words']} words, {payload['characters']} characters")],
        structured_content=payload,
    )


CORE_UTILS = NativeProvider(
    key="core_utils",
    name="Core Utilities",
    description="Built-in utility tools: current time and text statistics.",
    tools=[
        NativeToolSpec(
            name="current_time",
            title="Current Time",
            description="Get the current date and time in an IANA timezone (default UTC).",
            input_schema={
                "type": "object",
                "properties": {"timezone": {"type": "string", "description": "IANA timezone, e.g. Europe/London"}},
                "additionalProperties": False,
            },
            handler=_current_time,
            annotations={"read_only": True, "idempotent": True, "destructive": False, "open_world": False},
            default_enabled=True,
        ),
        NativeToolSpec(
            name="text_stats",
            title="Text Statistics",
            description="Count characters, words, and lines in a piece of text.",
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 100000}},
                "required": ["text"],
                "additionalProperties": False,
            },
            handler=_text_stats,
            annotations={"read_only": True, "idempotent": True, "destructive": False, "open_world": False},
            default_enabled=True,
        ),
    ],
)


def build_default_native_registry() -> NativeProviderRegistry:
    registry = NativeProviderRegistry()
    registry.register(CORE_UTILS)
    return registry


def require_provider(registry: NativeProviderRegistry, key: Any) -> NativeProvider:
    provider = registry.get(str(key)) if key else None
    if provider is None:
        raise BadRequestError(f"Unknown native provider '{str(key)[:60]}'")
    return provider
