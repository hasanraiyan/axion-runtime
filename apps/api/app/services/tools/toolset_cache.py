"""
ToolsetCache: a short-TTL, process-wide cache of *listed* toolsets (SRS-07 NFR-P1).

Only listing is cached. Invocation always resolves the single tool fresh (``ToolsetResolver.resolve_one``), so a stale
entry can at worst show a tool that the gateway then refuses; it can never authorise a call.

Entries are keyed by (project, subject, agent) and dropped when the project publishes ``ToolsetChanged``. A per-project
generation counter stops a build that raced with an invalidation from storing its (possibly stale) result.
In a multi-process deployment other processes see a change within the TTL.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional, Tuple

DEFAULT_TTL_SECONDS = 30.0
DEFAULT_MAX_ENTRIES = 2000

Key = Tuple[str, str, Optional[str]]


class ToolsetCache:
    def __init__(
        self, ttl: float = DEFAULT_TTL_SECONDS, max_entries: int = DEFAULT_MAX_ENTRIES, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._items: Dict[Key, Tuple[float, Any]] = {}
        self._generation: Dict[str, int] = {}

    @staticmethod
    def key(project_id: Any, subject_key: str, agent_id: Optional[str]) -> Key:
        return (str(project_id), subject_key, agent_id)

    def generation(self, project_id: Any) -> int:
        return self._generation.get(str(project_id), 0)

    def get(self, key: Key) -> Optional[Any]:
        item = self._items.get(key)
        if item is None:
            return None
        if item[0] <= self._clock():
            self._items.pop(key, None)
            return None
        return item[1]

    def put(self, key: Key, value: Any, generation: int) -> None:
        if self._ttl <= 0:
            return  # caching disabled
        if generation != self.generation(key[0]):
            return  # the project changed while this was being built
        if len(self._items) >= self._max and key not in self._items:
            now = self._clock()
            for k in [k for k, (exp, _) in self._items.items() if exp <= now]:
                self._items.pop(k, None)
            if len(self._items) >= self._max:
                self._items.pop(next(iter(self._items)), None)  # oldest insertion
        self._items[key] = (self._clock() + self._ttl, value)

    def invalidate_project(self, project_id: Any) -> None:
        pid = str(project_id)
        self._generation[pid] = self._generation.get(pid, 0) + 1
        for key in [k for k in self._items if k[0] == pid]:
            self._items.pop(key, None)

    async def on_toolset_changed(self, event: Any) -> None:
        self.invalidate_project(event.project_id)

    def __len__(self) -> int:
        return len(self._items)
