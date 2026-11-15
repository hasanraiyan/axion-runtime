"""
PolicyReader: the project tool policy for hot paths (toolset resolution, rate limiting, recording, discovery).

A short TTL cache keeps these paths off the database. Updates through ``ToolPolicyService`` invalidate the entry in
this process; in a multi-process deployment other processes see a change within the TTL (30 s by default).
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional, Tuple

from app.core.protocols.tool_repositories import IToolPolicyRepository
from app.core.tools.policy import EffectivePolicy


class PolicyCache:
    def __init__(self, ttl: float = 30.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl
        self._clock = clock
        self._items: Dict[str, Tuple[float, EffectivePolicy]] = {}

    def get(self, project_id: str) -> Optional[EffectivePolicy]:
        item = self._items.get(project_id)
        if item is None or item[0] <= self._clock():
            self._items.pop(project_id, None)
            return None
        return item[1]

    def put(self, project_id: str, policy: EffectivePolicy) -> None:
        self._items[project_id] = (self._clock() + self._ttl, policy)

    def invalidate(self, project_id: Any) -> None:
        self._items.pop(str(project_id), None)


class PolicyReader:
    def __init__(self, policy_repo: IToolPolicyRepository, cache: PolicyCache) -> None:
        self._policies = policy_repo
        self._cache = cache

    async def get(self, project_id: Any) -> EffectivePolicy:
        key = str(project_id)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        doc = await self._policies.get(project_id)
        effective = (
            EffectivePolicy(
                end_user_connect_enabled=doc.end_user_connect_enabled,
                allowed_return_origins=list(doc.allowed_return_origins),
                default_approval_policy=doc.default_approval_policy,
                content_retention_days=doc.invocation_content_retention_days,
                end_user_default_rate_limit_per_minute=doc.end_user_default_rate_limit_per_minute,
            )
            if doc is not None
            else EffectivePolicy()
        )
        self._cache.put(key, effective)
        return effective
