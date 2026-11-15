"""
In-memory access-token cache with single-flight fetching (SRS-07 FR-24, OAuth client credentials).

Machine-to-machine tokens are cheap to re-obtain, so they are never persisted: they live only in this process's memory
and a restart simply fetches a new one. Concurrent callers for the same key share one token request. A token is reused
until ``skew`` seconds before it expires. An entry carries a *fingerprint* (a digest of the client secret), so rotating the
secret makes the old token unusable at once instead of at expiry.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Hashable, Optional

from app.core.tools.oauth import TokenSet

DEFAULT_SKEW_SECONDS = 60.0
DEFAULT_TTL_SECONDS = 300.0  # when the server does not say how long a token lives, assume a short life
MAX_TTL_SECONDS = 3600.0


@dataclass
class _Entry:
    token: str
    expires_at: float
    fingerprint: str


class TokenCache:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        skew: float = DEFAULT_SKEW_SECONDS,
        default_ttl: float = DEFAULT_TTL_SECONDS,
        max_entries: int = 1000,
    ) -> None:
        self._clock = clock
        self._skew = skew
        self._default_ttl = default_ttl
        self._max = max_entries
        self._entries: Dict[Hashable, _Entry] = {}
        self._locks: Dict[Hashable, list] = {}  # key -> [lock, number of callers using it]

    def _fresh(self, key: Hashable, fingerprint: str) -> Optional[str]:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.fingerprint != fingerprint or entry.expires_at <= self._clock():
            self._entries.pop(key, None)
            return None
        return entry.token

    async def get(self, key: Hashable, fingerprint: str, fetch: Callable[[], Awaitable[TokenSet]]) -> str:
        cached = self._fresh(key, fingerprint)
        if cached is not None:
            return cached
        slot = self._locks.setdefault(key, [asyncio.Lock(), 0])
        slot[1] += 1  # callers using this lock; it is dropped when the last one leaves
        try:
            async with slot[0]:
                cached = self._fresh(key, fingerprint)  # another caller may have fetched while we waited
                if cached is not None:
                    return cached
                tokens = await fetch()
                self._store(key, fingerprint, tokens)
                return tokens.access_token
        finally:
            slot[1] -= 1
            if slot[1] == 0:
                self._locks.pop(key, None)

    def _store(self, key: Hashable, fingerprint: str, tokens: TokenSet) -> None:
        ttl = float(tokens.expires_in) if tokens.expires_in else self._default_ttl
        lifetime = min(ttl, MAX_TTL_SECONDS) - self._skew
        if lifetime <= 0:
            return  # too short-lived to reuse safely: every call fetches its own
        if len(self._entries) >= self._max and key not in self._entries:
            now = self._clock()
            for stale in [k for k, e in self._entries.items() if e.expires_at <= now]:
                self._entries.pop(stale, None)
            if len(self._entries) >= self._max:
                self._entries.pop(next(iter(self._entries)), None)
        self._entries[key] = _Entry(tokens.access_token, self._clock() + lifetime, fingerprint)

    def invalidate(self, key: Hashable) -> None:
        self._entries.pop(key, None)

    def __len__(self) -> int:
        return len(self._entries)
