"""
CatalogSyncSubscriber (SRS-07 FR-10): reacts to an MCP server announcing that its catalog changed.

Subscribes to ``McpListChanged`` events (published by the MCP connector) and re-discovers, so an upstream change
shows up without an admin pressing a button. Discovery keeps every safety rule: new tools arrive *disabled*, changed
tools are *suspended* until re-approved, and apps are re-pinned but never approved.

- Bursts are coalesced: one re-discovery per integration per debounce window; a notification that arrives while a
  re-discovery is running schedules exactly one more run, so no change is lost and none is processed twice.
- Per-user integrations are **not** re-discovered automatically: tools can differ per user, and discovery must run
  with one specific person's credentials, so the catalog is marked ``catalog_stale`` for an admin to refresh.
- Nothing here can break the MCP session that delivered the notification or crash the process: failures are logged.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Set

from app.core.tools.events import McpListChanged
from app.models.integration import CredentialMode

logger = logging.getLogger(__name__)
SYSTEM_ACTOR = "system:mcp-list-changed"


@dataclass
class _State:
    dirty: bool = False


class CatalogSyncSubscriber:
    def __init__(
        self,
        container_factory: Callable[[], Any],
        *,
        debounce: float = 5.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._factory = container_factory
        self._debounce = debounce
        self._sleep = sleep
        self._state: Dict[str, _State] = {}
        self._tasks: Set["asyncio.Task[None]"] = set()

    async def handle(self, event: McpListChanged) -> None:
        state = self._state.get(event.integration_id)
        if state is not None:
            state.dirty = True  # a run is pending or in progress: it will run once more, covering this notification
            return
        self._state[event.integration_id] = _State()
        task = asyncio.create_task(self._run(event), name=f"catalog-sync-{event.integration_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, event: McpListChanged) -> None:
        state = self._state[event.integration_id]
        try:
            while True:
                await self._sleep(self._debounce)  # let a burst of notifications settle
                state.dirty = False
                try:
                    await self._sync(event)
                except Exception:
                    logger.exception("Catalog re-sync failed for integration %s", event.integration_id)
                if not state.dirty:
                    return
        finally:
            self._state.pop(event.integration_id, None)

    async def _sync(self, event: McpListChanged) -> None:
        if event.kind == "prompts":
            return  # prompts are listed live, never persisted
        container = self._factory()
        integration = await container.integrations.get(event.project_id, event.integration_id)  # not found if deleted
        if not integration.is_enabled:
            return

        if event.kind == "resources":
            if integration.auth_profile.credential_mode != CredentialMode.PER_USER:
                await container.apps.sync_integration(event.project_id, event.integration_id, SYSTEM_ACTOR)
            return

        if integration.auth_profile.credential_mode == CredentialMode.PER_USER:
            await container.discovery.mark_stale(event.project_id, event.integration_id)
            return
        await container.discovery.discover(event.project_id, event.integration_id, SYSTEM_ACTOR)
        try:
            await container.apps.sync_integration(event.project_id, event.integration_id, SYSTEM_ACTOR)
        except Exception:  # apps are optional; a catalog refresh must not fail because of them
            logger.debug("App re-sync skipped for integration %s", event.integration_id, exc_info=True)

    async def wait_idle(self) -> None:
        """Wait until every scheduled re-discovery has finished (graceful shutdown and tests)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def shutdown(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
