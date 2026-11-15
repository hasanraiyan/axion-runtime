"""
In-process resilience primitives for the Gateway (SRS-07 FR-38, FR-36, FR-82):
circuit breaker, sliding-window rate limiter, and idempotency store. State is held per
process; a shared store can replace them behind the same small interfaces.
"""
from __future__ import annotations

import asyncio
import time
import weakref
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional

Clock = Callable[[], float]


class CircuitBreaker:
    """Opens after ``threshold`` consecutive failures inside ``window``; half-opens after ``cooldown``."""

    def __init__(
        self, threshold: int = 3, window: float = 60.0, cooldown: float = 60.0, clock: Clock = time.monotonic
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._cooldown = cooldown
        self._clock = clock
        self._failures: Dict[str, Deque[float]] = {}
        self._opened_at: Dict[str, float] = {}

    def allow(self, key: str) -> bool:
        opened = self._opened_at.get(key)
        if opened is None:
            return True
        if self._clock() - opened >= self._cooldown:
            return True  # half-open: let a probe through; success/failure below decides
        return False

    def is_open(self, key: str) -> bool:
        return not self.allow(key)

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._opened_at.pop(key, None)

    def record_failure(self, key: str) -> bool:
        """Record a failure; return ``True`` if this failure opened (or re-opened) the breaker."""
        now = self._clock()
        failures = self._failures.setdefault(key, deque())
        failures.append(now)
        while failures and now - failures[0] > self._window:
            failures.popleft()
        if key in self._opened_at and now - self._opened_at[key] >= self._cooldown:
            self._opened_at[key] = now  # half-open probe failed: re-open
            return True
        if len(failures) >= self._threshold and key not in self._opened_at:
            self._opened_at[key] = now
            return True
        return False

    def consecutive_failures(self, key: str) -> int:
        return len(self._failures.get(key, ()))


class SlidingWindowRateLimiter:
    def __init__(self, window: float = 60.0, clock: Clock = time.monotonic) -> None:
        self._window = window
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = {}

    def check_and_hit(self, key: str, limit: Optional[int]) -> bool:
        """Return ``True`` if the call is allowed (and count it); ``False`` if over the limit."""
        if limit is None:
            return True
        now = self._clock()
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] > self._window:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True


@dataclass
class _Stored:
    value: object
    expires_at: float


class IdempotencyStore:
    def __init__(self, ttl: float = 600.0, max_entries: int = 10000, clock: Clock = time.monotonic) -> None:
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._items: "OrderedDict[str, _Stored]" = OrderedDict()

    def get(self, key: str) -> Optional[object]:
        item = self._items.get(key)
        if item is None:
            return None
        if item.expires_at <= self._clock():
            self._items.pop(key, None)
            return None
        return item.value

    def put(self, key: str, value: object) -> None:
        self._items[key] = _Stored(value, self._clock() + self._ttl)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)


class KeyedLocks:
    """Per-key asyncio locks held weakly, so idle keys are garbage-collected (single-flight token refresh)."""

    def __init__(self) -> None:
        self._locks: "weakref.WeakValueDictionary[str, asyncio.Lock]" = weakref.WeakValueDictionary()

    def lock(self, key: str) -> asyncio.Lock:
        existing = self._locks.get(key)
        if existing is None:
            existing = asyncio.Lock()
            self._locks[key] = existing
        return existing
