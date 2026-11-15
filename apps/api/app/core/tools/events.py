"""
Domain events (Dependency Inversion): Module 07 publishes facts; consumers such as the
agent runtime or caches subscribe. This module never calls into the agent runtime.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Type

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolsetChanged:
    project_id: str
    reason: str = ""


@dataclass(frozen=True)
class ConnectionChanged:
    project_id: str
    integration_id: str
    subject_key: str


@dataclass(frozen=True)
class McpListChanged:
    """An MCP server announced that its tools, resources, or prompts changed (SRS-07 FR-10)."""

    project_id: str
    integration_id: str
    kind: str  # tools | resources | prompts


@dataclass(frozen=True)
class McpSessionsInvalidated:
    """Pooled MCP sessions for an integration must be closed (credentials, endpoint, or state changed)."""

    project_id: str
    integration_id: str
    reason: str = ""


@dataclass(frozen=True)
class EndUserBlocked:
    project_id: str
    end_user_id: str


Handler = Callable[[Any], Awaitable[None]]


class InProcessEventBus:
    """Minimal in-process bus. A queue-backed implementation can replace it behind ``DomainEventPort``."""

    def __init__(self) -> None:
        self._handlers: Dict[Type[Any], List[Handler]] = {}

    def subscribe(self, event_type: Type[Any], handler: Handler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    async def publish(self, event: Any) -> None:
        for handler in self._handlers.get(type(event), []):
            try:
                await handler(event)
            except Exception:  # a failing subscriber must never break the publisher
                logger.exception("Domain event handler failed for %s", type(event).__name__)


_default_bus = InProcessEventBus()


def get_event_bus() -> InProcessEventBus:
    return _default_bus
