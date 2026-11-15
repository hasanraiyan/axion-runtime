"""
MCP session pool (SRS-07 FR-18, FR-81).

Reuses initialized MCP sessions across tool calls instead of paying a handshake per call.

Ownership: the SDK's sessions use ``anyio`` task groups, which must be entered and exited in the *same task*.
So each pooled session is owned by a dedicated background task that opens it, parks until it is told to close
(or has been idle too long), and closes it. Callers use the session from their own tasks through a small proxy,
which is safe; only the lifecycle lives in the owner.

Isolation: a session is keyed by ``(integration, integration revision, credential fingerprint)``. Different
subjects hold different credentials, so they can never share a per-user session; a shared (project) credential is
one session for everyone, which is exactly the project-shared semantics. The fingerprint is a keyed hash held only in
memory, never the credential.

Bounds: a per-integration and a global cap, least-recently-used idle eviction, and per-user sessions use a shorter idle
TTL. If a cap is reached and nothing is idle, the caller simply gets an unpooled session, so the pool never blocks.

Safety: any failure on a pooled session evicts it (its connection state is unknown). Only "session expired" (the server
says it never saw the request) is retried, once, on a fresh session, so a tool call is never executed twice.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

from app.core.tools.errors import UpstreamError, UpstreamSessionExpired
from app.core.tools.types import ResolvedCredentials
from app.integrations.mcp_client import McpConnectorPort, McpSessionPort, map_sdk_exception
from app.models.integration import CredentialMode, Integration

Opener = Callable[[], AbstractAsyncContextManager[McpSessionPort]]


@dataclass(frozen=True)
class PoolKey:
    integration_id: str
    revision: int
    fingerprint: str


class _Entry:
    def __init__(self, key: PoolKey, idle_ttl: float, clock: Callable[[], float]) -> None:
        self.key = key
        self.idle_ttl = idle_ttl
        self.session: Optional[McpSessionPort] = None
        self.ready: "asyncio.Future[None]" = asyncio.get_running_loop().create_future()
        self.ready.add_done_callback(lambda f: f.cancelled() or f.exception())  # never "exception was never retrieved"
        self.closing = asyncio.Event()
        self.refcount = 0
        self.last_used = clock()
        self.broken = False
        self.closed = False
        self.task: Optional["asyncio.Task[None]"] = None


class McpSessionPool:
    def __init__(
        self,
        *,
        idle_ttl: float = 300.0,
        per_user_idle_ttl: float = 120.0,
        max_per_integration: int = 8,
        max_total: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._idle_ttl = idle_ttl
        self._per_user_idle_ttl = per_user_idle_ttl
        self._max_per_integration = max_per_integration
        self._max_total = max_total
        self._clock = clock
        self._entries: Dict[PoolKey, _Entry] = {}
        self._pepper = os.urandom(32)
        self.stats: Dict[str, int] = {"opened": 0, "reused": 0, "idle_closed": 0, "evicted": 0, "unpooled": 0, "failed": 0, "broken": 0}

    # ------------------------------------------------------------------ helpers
    def fingerprint(self, credentials: ResolvedCredentials) -> str:
        """Keyed hash of the credential material: distinguishes credentials without ever storing them."""
        material = "\n".join(sorted(f"h:{k}:{v}" for k, v in credentials.headers.items()) + sorted(f"q:{k}:{v}" for k, v in credentials.query.items()))
        return hashlib.blake2b(material.encode("utf-8"), key=self._pepper, digest_size=16).hexdigest()

    def size(self, integration_id: Optional[str] = None) -> int:
        return sum(1 for k in self._entries if integration_id is None or k.integration_id == integration_id)

    def _evict_lru_idle(self, predicate: Callable[[PoolKey], bool]) -> bool:
        idle = [e for k, e in self._entries.items() if predicate(k) and e.refcount == 0 and not e.closed]
        if not idle:
            return False
        victim = min(idle, key=lambda e: e.last_used)
        self._discard(victim)
        self.stats["evicted"] += 1
        return True

    def _discard(self, entry: _Entry) -> None:
        if self._entries.get(entry.key) is entry:
            del self._entries[entry.key]
        entry.closing.set()

    # ---------------------------------------------------------------- lifecycle
    async def _run(self, entry: _Entry, opener: Opener) -> None:
        """Owner task: open the session, park, close it, all in this one task (anyio requirement)."""
        try:
            async with opener() as session:
                entry.session = session
                if not entry.ready.done():
                    entry.ready.set_result(None)
                while not entry.closing.is_set():
                    remaining = max(entry.idle_ttl - (self._clock() - entry.last_used), 0.01)
                    try:
                        await asyncio.wait_for(entry.closing.wait(), timeout=remaining)
                    except asyncio.TimeoutError:
                        if entry.refcount == 0 and self._clock() - entry.last_used >= entry.idle_ttl:
                            self.stats["idle_closed"] += 1
                            break
        except BaseException as exc:  # noqa: BLE001 - surfaced to waiters below
            entry.broken = True
            if not entry.ready.done():
                self.stats["failed"] += 1
                entry.ready.set_exception(exc if isinstance(exc, Exception) else UpstreamError("The MCP session was cancelled"))
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            entry.closed = True
            if self._entries.get(entry.key) is entry:
                del self._entries[entry.key]

    async def acquire(self, key: PoolKey, opener: Opener, per_user: bool) -> Optional[_Entry]:
        """
        Return a ready pooled entry (refcount held; call ``release``), or ``None`` when the caller should use an
        unpooled session because a cap was reached with nothing idle to evict.
        """
        entry = self._entries.get(key)
        if entry is not None and (entry.closed or entry.broken or entry.closing.is_set()):
            entry = None
        if entry is not None:
            self.stats["reused"] += 1
        else:
            while self.size(key.integration_id) >= self._max_per_integration:
                if not self._evict_lru_idle(lambda k: k.integration_id == key.integration_id):
                    self.stats["unpooled"] += 1
                    return None
            while self.size() >= self._max_total:
                if not self._evict_lru_idle(lambda k: True):
                    self.stats["unpooled"] += 1
                    return None
            entry = _Entry(key, self._per_user_idle_ttl if per_user else self._idle_ttl, self._clock)
            self._entries[key] = entry
            self.stats["opened"] += 1
            entry.task = asyncio.create_task(self._run(entry, opener), name=f"mcp-pool-{key.integration_id}")
        entry.refcount += 1
        try:
            await asyncio.shield(entry.ready)
        except BaseException:
            self._release_ref(entry)
            raise
        return entry

    def _release_ref(self, entry: _Entry) -> None:
        entry.refcount = max(entry.refcount - 1, 0)
        entry.last_used = self._clock()
        if entry.broken:
            self._discard(entry)

    def release(self, entry: _Entry) -> None:
        self._release_ref(entry)

    def mark_broken(self, entry: _Entry) -> None:
        if not entry.broken:
            self.stats["broken"] += 1
        entry.broken = True
        self._discard(entry)

    # ----------------------------------------------------------------- eviction
    async def evict_integration(self, integration_id: str) -> int:
        """Close every pooled session of an integration (credentials or endpoint changed, or it was removed)."""
        victims = [e for k, e in self._entries.items() if k.integration_id == integration_id]
        for entry in victims:
            self._discard(entry)
        await self._await_closed(victims)
        return len(victims)

    async def close_all(self) -> None:
        victims = list(self._entries.values())
        for entry in victims:
            self._discard(entry)
        await self._await_closed(victims)

    @staticmethod
    async def _await_closed(entries: List[_Entry]) -> None:
        tasks = [e.task for e in entries if e.task is not None]
        if tasks:
            await asyncio.wait(tasks, timeout=5.0)


class _PooledSession:
    """Proxy a caller uses in place of the owner's session; maps and classifies failures, evicts on error."""

    def __init__(self, pool: McpSessionPool, entry: _Entry, reacquire: Callable[[], Any]) -> None:
        self._pool = pool
        self._entry = entry
        self._reacquire = reacquire
        self._retried = False

    @property
    def entry(self) -> _Entry:
        return self._entry

    @property
    def server_info(self) -> Dict[str, Any]:
        return self._entry.session.server_info  # type: ignore[union-attr]

    @property
    def capabilities(self) -> Dict[str, Any]:
        return self._entry.session.capabilities  # type: ignore[union-attr]

    @property
    def protocol_version(self) -> Optional[str]:
        return self._entry.session.protocol_version  # type: ignore[union-attr]

    async def _invoke(self, name: str, *args: Any) -> Any:
        entry = self._entry
        session: Any = entry.session
        statuses: List[int] = getattr(session, "http_statuses", [])
        statuses.clear()
        try:
            return await getattr(session, name)(*args)
        except BaseException as exc:  # noqa: BLE001
            self._pool.mark_broken(entry)  # connection state is unknown after any failure
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            mapped = map_sdk_exception(exc, list(statuses))
            if isinstance(mapped, UpstreamSessionExpired) and not self._retried:
                # The server never saw the request, so replaying it on a fresh session cannot double-execute it.
                self._retried = True
                fresh = await self._reacquire()
                if fresh is not None:
                    self._pool.release(entry)
                    self._entry = fresh
                    return await self._invoke(name, *args)
            raise mapped from exc

    async def list_tools(self) -> List[Dict[str, Any]]:
        return await self._invoke("list_tools")

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self._invoke("call_tool", name, arguments)

    async def list_resources(self) -> List[Dict[str, Any]]:
        return await self._invoke("list_resources")

    async def list_resource_templates(self) -> List[Dict[str, Any]]:
        return await self._invoke("list_resource_templates")

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        return await self._invoke("read_resource", uri)

    async def list_prompts(self) -> List[Dict[str, Any]]:
        return await self._invoke("list_prompts")


class PooledMcpConnector:
    """``McpConnectorPort`` that serves sessions from a pool; everything else about connecting is the inner connector's."""

    def __init__(self, inner: McpConnectorPort, pool: McpSessionPool) -> None:
        self._inner = inner
        self._pool = pool

    @asynccontextmanager
    async def connect(self, integration: Integration, credentials: ResolvedCredentials) -> AsyncIterator[McpSessionPort]:
        key = PoolKey(str(integration.id), integration.revision, self._pool.fingerprint(credentials))
        per_user = integration.auth_profile.credential_mode == CredentialMode.PER_USER

        def opener() -> AbstractAsyncContextManager[McpSessionPort]:
            return self._inner.connect(integration, credentials)

        entry = await self._pool.acquire(key, opener, per_user)
        if entry is None:  # at capacity with nothing idle: use a one-off session rather than wait
            async with opener() as session:
                yield session
            return

        proxy = _PooledSession(self._pool, entry, lambda: self._pool.acquire(key, opener, per_user))
        try:
            yield proxy  # type: ignore[misc]
        finally:
            self._pool.release(proxy.entry)
