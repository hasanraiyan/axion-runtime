"""
MCP session pool unit tests (SRS-07 FR-18, FR-81). A fake inner connector makes every lifecycle edge deterministic:
ownership, reuse, idle expiry, isolation, caps, failure handling, retry, cancellation. No network, no database.
"""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

from app.core.tools.errors import UpstreamAuthError, UpstreamError, UpstreamSessionExpired
from app.core.tools.types import ResolvedCredentials
from app.integrations.mcp_pool import McpSessionPool, PooledMcpConnector
from app.models.integration import CredentialMode


class HttpError(Exception):
    """Looks like the HTTP errors the SDK surfaces: carries a response with a status code."""

    def __init__(self, status: int) -> None:
        super().__init__(f"http {status}")
        self.response = SimpleNamespace(status_code=status)


class FakeSession:
    def __init__(self, ident: int) -> None:
        self.id = ident
        self.http_statuses: List[int] = []
        self.server_info = {"name": "fake"}
        self.capabilities = {"tools": {}}
        self.protocol_version = "2025-06-18"
        self.calls: List[str] = []
        self.next_error: Optional[BaseException] = None
        self.delay = 0.0

    async def call_tool(self, name: str, arguments: dict) -> dict:
        self.calls.append(name)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.next_error is not None:
            error, self.next_error = self.next_error, None
            raise error
        return {"content": [{"type": "text", "text": f"s{self.id}:{name}"}]}

    async def list_tools(self) -> list:
        return [{"name": "t"}]

    async def list_resources(self) -> list:
        return []

    async def list_resource_templates(self) -> list:
        return []

    async def read_resource(self, uri: str) -> dict:
        return {"uri": uri, "text": "x"}

    async def list_prompts(self) -> list:
        return []


class FakeConnector:
    def __init__(self) -> None:
        self.sessions: List[FakeSession] = []
        self.closed: List[FakeSession] = []
        self.same_task_lifecycle: List[bool] = []
        self.fail_open: Optional[BaseException] = None
        self.open_delay = 0.0
        self.on_open: Optional[Any] = None

    def connect(self, integration: Any, credentials: Any):
        outer = self

        @asynccontextmanager
        async def cm():
            if outer.fail_open is not None:
                raise outer.fail_open
            if outer.open_delay:
                await asyncio.sleep(outer.open_delay)
            session = FakeSession(len(outer.sessions))
            outer.sessions.append(session)
            entered_in = asyncio.current_task()
            if outer.on_open:
                outer.on_open(session)
            try:
                yield session
            finally:
                outer.closed.append(session)
                outer.same_task_lifecycle.append(asyncio.current_task() is entered_in)

        return cm()


def integration(ident: str = "i1", revision: int = 1, per_user: bool = False) -> Any:
    mode = CredentialMode.PER_USER if per_user else CredentialMode.PROJECT_SHARED
    return SimpleNamespace(id=ident, revision=revision, auth_profile=SimpleNamespace(credential_mode=mode), config={})


def creds(token: str = "t1") -> ResolvedCredentials:
    return ResolvedCredentials(headers={"Authorization": f"Bearer {token}"})


async def call(connector: PooledMcpConnector, integ: Any, c: ResolvedCredentials, name: str = "x") -> str:
    async with connector.connect(integ, c) as session:
        result = await session.call_tool(name, {})
        return result["content"][0]["text"]


def make(**pool_kwargs: Any):
    inner = FakeConnector()
    pool = McpSessionPool(**pool_kwargs)
    return inner, pool, PooledMcpConnector(inner, pool)


# ===================================================================== reuse and ownership
async def test_sequential_calls_reuse_one_session():
    inner, pool, conn = make()
    results = [await call(conn, integration(), creds()) for _ in range(5)]
    assert results == ["s0:x"] * 5 and len(inner.sessions) == 1
    assert pool.stats["opened"] == 1 and pool.stats["reused"] == 4
    await pool.close_all()


async def test_concurrent_callers_share_a_single_open():
    inner, pool, conn = make()
    inner.open_delay = 0.05
    results = await asyncio.gather(*[call(conn, integration(), creds(), f"c{i}") for i in range(12)])
    assert len(inner.sessions) == 1 and pool.stats["opened"] == 1
    assert sorted(r.split(":")[1] for r in results) == sorted(f"c{i}" for i in range(12))
    await pool.close_all()


async def test_the_session_is_always_entered_and_exited_in_one_owner_task():
    """The SDK's anyio scopes break if the exit happens in a different task: this is the pool's core invariant."""
    inner, pool, conn = make(idle_ttl=0.05)
    await call(conn, integration("a"), creds())
    await call(conn, integration("b"), creds())
    await call(conn, integration("c"), creds())
    await pool.evict_integration("b")
    await asyncio.sleep(0.2)  # a and c close by idle expiry, b by eviction
    await call(conn, integration("d"), creds())
    await pool.close_all()
    assert len(inner.closed) == 4 and all(inner.same_task_lifecycle)


# ===================================================================== idle behaviour
async def test_idle_sessions_close_and_the_next_call_opens_a_fresh_one():
    inner, pool, conn = make(idle_ttl=0.05)
    await call(conn, integration(), creds())
    await asyncio.sleep(0.25)
    assert pool.size() == 0 and pool.stats["idle_closed"] == 1 and len(inner.closed) == 1
    assert await call(conn, integration(), creds()) == "s1:x"
    assert pool.stats["opened"] == 2
    await pool.close_all()


async def test_a_session_in_use_is_never_closed_by_the_idle_timer():
    inner, pool, conn = make(idle_ttl=0.05)
    async with conn.connect(integration(), creds()) as session:
        await asyncio.sleep(0.25)  # far longer than the idle TTL, but the lease is held
        assert (await session.call_tool("still-here", {}))["content"][0]["text"] == "s0:still-here"
        assert not inner.closed
    await pool.close_all()


async def test_per_user_sessions_expire_sooner_than_shared_ones():
    inner, pool, conn = make(idle_ttl=30.0, per_user_idle_ttl=0.05)
    await call(conn, integration("shared"), creds("a"))
    await call(conn, integration("peruser", per_user=True), creds("b"))
    await asyncio.sleep(0.25)
    assert pool.size("peruser") == 0 and pool.size("shared") == 1
    await pool.close_all()


# ===================================================================== isolation
async def test_different_credentials_never_share_a_session():
    inner, pool, conn = make()
    ann = await call(conn, integration(per_user=True), creds("ann-token"))
    bob = await call(conn, integration(per_user=True), creds("bob-token"))
    assert ann != bob and len(inner.sessions) == 2  # per-user means per-credential
    assert await call(conn, integration(per_user=True), creds("ann-token")) == ann  # and reuse is per credential
    await pool.close_all()


async def test_integration_and_revision_are_part_of_the_key():
    inner, pool, conn = make()
    await call(conn, integration("i1", 1), creds())
    await call(conn, integration("i2", 1), creds())
    await call(conn, integration("i1", 2), creds())  # the integration was reconfigured
    assert len(inner.sessions) == 3
    await pool.close_all()


async def test_fingerprints_distinguish_credentials_without_containing_them():
    pool = McpSessionPool()
    a, b = pool.fingerprint(creds("super-secret-token")), pool.fingerprint(creds("other-token"))
    assert a != b and a == pool.fingerprint(creds("super-secret-token"))
    assert "super-secret-token" not in a and len(a) == 32
    assert McpSessionPool().fingerprint(creds("super-secret-token")) != a  # keyed per process: not a portable hash
    q = pool.fingerprint(ResolvedCredentials(query={"k": "v"}))
    assert q != pool.fingerprint(ResolvedCredentials(headers={"k": "v"}))  # placement matters


# ===================================================================== caps
async def test_per_integration_cap_evicts_the_least_recently_used_idle_session():
    inner, pool, conn = make(max_per_integration=2)
    await call(conn, integration(per_user=True), creds("u1"))
    await asyncio.sleep(0.01)
    await call(conn, integration(per_user=True), creds("u2"))
    await asyncio.sleep(0.01)
    await call(conn, integration(per_user=True), creds("u3"))  # evicts u1, the oldest idle
    assert pool.size("i1") == 2 and pool.stats["evicted"] == 1
    assert await call(conn, integration(per_user=True), creds("u1")) == "s3:x"  # u1 had to reopen
    await pool.close_all()


async def test_when_the_cap_is_reached_and_nothing_is_idle_the_caller_gets_an_unpooled_session():
    inner, pool, conn = make(max_per_integration=2)
    async with conn.connect(integration(per_user=True), creds("u1")), conn.connect(integration(per_user=True), creds("u2")):
        # Both pooled sessions are in use, so a third caller is served without waiting and without being pooled.
        assert await call(conn, integration(per_user=True), creds("u3")) == "s2:x"
        assert pool.stats["unpooled"] == 1 and pool.size("i1") == 2
        assert len(inner.closed) == 1  # the one-off session was closed straight away
    await pool.close_all()


async def test_the_global_cap_applies_across_integrations():
    inner, pool, conn = make(max_total=2)
    for name in ("a", "b", "c"):
        await call(conn, integration(name), creds())
        await asyncio.sleep(0.01)
    assert pool.size() == 2 and pool.stats["evicted"] == 1
    await pool.close_all()


# ===================================================================== failures
async def test_any_failure_evicts_the_session_and_the_next_call_reopens():
    inner, pool, conn = make()
    async with conn.connect(integration(), creds()) as session:
        inner.sessions[0].next_error = RuntimeError("connection reset")
        with pytest.raises(UpstreamError):
            await session.call_tool("x", {})
    assert pool.size() == 0 and pool.stats["broken"] == 1
    assert await call(conn, integration(), creds()) == "s1:x"
    await pool.close_all()


async def test_failures_are_classified_from_the_recorded_http_status():
    inner, pool, conn = make()
    async with conn.connect(integration(), creds()) as session:
        inner.sessions[0].http_statuses.append(401)

        class Opaque(Exception):  # the SDK reports HTTP failures without the status
            pass

        inner.sessions[0].next_error = Opaque("Server returned an error response")
        # statuses are cleared per call, so record the status as the transport would during the call
        original = inner.sessions[0].call_tool

        async def failing(name, arguments):
            inner.sessions[0].http_statuses.append(401)
            return await original(name, arguments)

        inner.sessions[0].call_tool = failing  # type: ignore[assignment]
        with pytest.raises(UpstreamAuthError):
            await session.call_tool("x", {})
    await pool.close_all()


async def test_session_expired_is_retried_once_on_a_fresh_session_and_executes_once():
    inner, pool, conn = make()
    async with conn.connect(integration(), creds()) as session:
        inner.sessions[0].next_error = HttpError(404)  # the server no longer knows this session
        result = await session.call_tool("work", {})
    assert result["content"][0]["text"] == "s1:work"
    assert inner.sessions[0].calls == ["work"] and inner.sessions[1].calls == ["work"]  # the failed attempt never ran
    assert pool.stats["opened"] == 2
    await pool.close_all()


async def test_session_expired_twice_is_not_retried_forever():
    inner, pool, conn = make()

    def arm(session: FakeSession) -> None:
        session.next_error = HttpError(404)

    inner.on_open = arm  # every fresh session is also "expired"
    async with conn.connect(integration(), creds()) as session:
        with pytest.raises(UpstreamSessionExpired):
            await session.call_tool("x", {})
    assert len(inner.sessions) == 2  # original plus exactly one retry
    await pool.close_all()


async def test_a_failing_open_fails_every_waiter_and_leaves_nothing_behind():
    inner, pool, conn = make()
    inner.fail_open = UpstreamAuthError("rejected")
    inner.open_delay = 0.0
    results = await asyncio.gather(*[call(conn, integration(), creds()) for _ in range(5)], return_exceptions=True)
    assert all(isinstance(r, UpstreamAuthError) for r in results)
    assert pool.size() == 0
    inner.fail_open = None
    assert await call(conn, integration(), creds()) == "s0:x"  # recovers on the next attempt
    await pool.close_all()


async def test_cancelling_a_caller_mid_call_evicts_the_session_and_does_not_hang():
    inner, pool, conn = make()
    started = asyncio.Event()

    async def slow():
        async with conn.connect(integration(), creds()) as session:
            inner.sessions[0].delay = 5.0
            started.set()
            await session.call_tool("slow", {})

    task = asyncio.create_task(slow())
    await started.wait()
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pool.size() == 0  # its connection state is unknown, so it must not be reused
    assert await call(conn, integration(), creds()) == "s1:x"
    await pool.close_all()


# ===================================================================== invalidation and shutdown
async def test_evicting_an_integration_closes_all_its_sessions_and_only_its_sessions():
    inner, pool, conn = make()
    await call(conn, integration("a", per_user=True), creds("1"))
    await call(conn, integration("a", per_user=True), creds("2"))
    await call(conn, integration("b"), creds())
    assert await pool.evict_integration("a") == 2
    assert pool.size("a") == 0 and pool.size("b") == 1 and len(inner.closed) == 2
    await pool.close_all()


async def test_close_all_closes_everything_and_waits_for_it():
    inner, pool, conn = make()
    for name in ("a", "b", "c"):
        await call(conn, integration(name), creds())
    await pool.close_all()
    assert pool.size() == 0 and len(inner.closed) == 3 and all(inner.same_task_lifecycle)


async def test_a_released_lease_does_not_leave_a_reference_count_behind():
    inner, pool, conn = make(idle_ttl=0.05)
    for _ in range(3):
        await call(conn, integration(), creds())
    await asyncio.sleep(0.25)
    assert pool.size() == 0  # refcount returned to zero, so the idle timer could close it
