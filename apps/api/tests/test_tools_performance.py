"""
Toolset cache, per-integration concurrency cap, and the SRS-07 performance targets (NFR-P1..P5).

The performance tests run against in-memory repositories, so they measure the platform's own logic and the cache, not
database or network latency. They guard against regressions (e.g. an accidental per-tool deepcopy), with generous
margins so they are not flaky on a slow CI machine.
"""
import asyncio
import statistics
import time
from typing import List

import pytest

from app.core.tools.events import ToolsetChanged
from app.core.tools.resilience import ConcurrencyLimiter
from app.services.tools.gateway_stages import concurrency_limit
from app.core.exceptions import BadRequestError, ProjectArchivedError
from app.integrations.adapters import McpAdapter
from app.models.project import ProjectStatus
from app.schemas.tools import ToolSettingUpdateRequest
from app.services.tools.toolset import visible_schema
from app.services.tools.toolset_cache import ToolsetCache
from tests.test_tools_services import MEMBER, ready, req
from tests.tools_harness import make_harness, tool

pytestmark = pytest.mark.usefixtures("tool_models")


def principal(h):
    return h.principal(MEMBER)


# ====================================================================== visible_schema
def test_visible_schema_does_not_mutate_the_stored_definition():
    schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}, "required": ["a", "b"]}
    shown = visible_schema(schema, {"a"})
    assert list(shown["properties"]) == ["b"] and shown["required"] == ["b"]
    assert list(schema["properties"]) == ["a", "b"] and schema["required"] == ["a", "b"]  # regression: no in-place edit


def test_visible_schema_drops_an_emptied_required_list_and_defaults_an_empty_schema():
    shown = visible_schema({"type": "object", "properties": {"a": {}}, "required": ["a"]}, {"a"})
    assert "required" not in shown and shown["properties"] == {}
    assert visible_schema({}, set()) == {"type": "object", "properties": {}}


# ====================================================================== cache unit
def test_cache_expires_after_the_ttl():
    now = [0.0]
    cache = ToolsetCache(ttl=10, clock=lambda: now[0])
    key = cache.key("p", "member:m", None)
    cache.put(key, "v", cache.generation("p"))
    assert cache.get(key) == "v"
    now[0] = 10.0
    assert cache.get(key) is None


def test_cache_invalidation_is_per_project():
    cache = ToolsetCache()
    a, b = cache.key("p1", "member:m", None), cache.key("p2", "member:m", None)
    cache.put(a, 1, cache.generation("p1"))
    cache.put(b, 2, cache.generation("p2"))
    cache.invalidate_project("p1")
    assert cache.get(a) is None and cache.get(b) == 2


def test_a_build_that_raced_with_an_invalidation_is_not_stored():
    cache = ToolsetCache()
    key = cache.key("p", "member:m", None)
    started = cache.generation("p")
    cache.invalidate_project("p")  # the project changed while the toolset was being built
    cache.put(key, "stale", started)
    assert cache.get(key) is None


def test_cache_is_bounded():
    cache = ToolsetCache(max_entries=3)
    for i in range(10):
        cache.put(cache.key("p", f"member:{i}", None), i, cache.generation("p"))
    assert len(cache) == 3


# ====================================================================== cache through the resolver
async def test_a_repeat_listing_is_served_without_touching_the_repositories():
    h = make_harness()
    await ready(h, [tool("a"), tool("b")])
    p = principal(h)
    first = await h.container.toolset.resolve_toolset(p)
    reads = {"n": 0}
    original = h.tools_repo.list_by_project

    async def counting(*a, **k):
        reads["n"] += 1
        return await original(*a, **k)

    h.tools_repo.list_by_project = counting  # type: ignore[method-assign]
    second = await h.container.toolset.resolve_toolset(p)
    assert reads["n"] == 0 and second.version == first.version and [t.tool_key for t in second.tools] == ["svc.a", "svc.b"]


async def test_the_cached_listing_is_a_copy_so_callers_cannot_poison_it():
    h = make_harness()
    await ready(h, [tool("a")])
    p = principal(h)
    await h.container.toolset.resolve_toolset(p)  # miss: fills the cache
    hit = await h.container.toolset.resolve_toolset(p)  # hit: must be a copy of the stored listing
    hit.tools.clear()
    assert [t.tool_key for t in (await h.container.toolset.resolve_toolset(p)).tools] == ["svc.a"]


async def test_disabling_a_tool_is_visible_in_the_next_listing():
    h = make_harness()
    await ready(h, [tool("a"), tool("b")])
    p = principal(h)
    assert len((await h.container.toolset.resolve_toolset(p)).tools) == 2
    _, setting = await h.container.catalog.get_tool(h.project.id, "svc.b")
    await h.container.tool_settings.update(h.project.id, "svc.b", ToolSettingUpdateRequest(revision=setting.revision, is_enabled=False), "admin")
    assert [t.tool_key for t in (await h.container.toolset.resolve_toolset(p)).tools] == ["svc.a"]


async def test_listings_are_cached_per_subject_and_agent():
    h = make_harness()
    await ready(h, [tool("a")])
    cache = h.shared.toolset_cache
    await h.container.toolset.resolve_toolset(h.principal(MEMBER))
    await h.container.toolset.resolve_toolset(h.principal(MEMBER, agent_id="agent-1"))
    assert len(cache) == 2


async def test_an_expired_entry_is_rebuilt_from_current_data():
    h = make_harness()
    await ready(h, [tool("a")])
    p = principal(h)
    await h.container.toolset.resolve_toolset(p)
    # Simulate another process changing the data: no event reaches this process, so only the TTL bounds staleness.
    for key in list(h.settings_repo.items):
        h.settings_repo.items[key].is_enabled = False
    assert len((await h.container.toolset.resolve_toolset(p)).tools) == 1
    h.shared.toolset_cache._ttl = 0  # noqa: SLF001
    h.shared.toolset_cache.invalidate_project(h.pid)
    assert (await h.container.toolset.resolve_toolset(p)).tools == []


async def test_invocation_never_uses_the_listing_cache():
    """A stale listing can show a tool, but the gateway re-resolves it fresh and refuses a disabled one."""
    h = make_harness()
    await ready(h, [tool("a")])
    await h.container.toolset.resolve_toolset(principal(h))  # warm the cache
    for key in list(h.settings_repo.items):
        h.settings_repo.items[key].is_enabled = False  # no event: the cache is stale
    result = await h.container.gateway.invoke(req(h, "svc.a", {"q": "x"}))
    assert result.ok is False


async def test_an_archived_project_does_not_get_a_cached_listing():
    """The project lifecycle is checked on every call, so a warm cache cannot outlive an archive."""
    h = make_harness()
    await ready(h, [tool("a")])
    p = principal(h)
    await h.container.toolset.resolve_toolset(p)
    h.project.status = ProjectStatus.ARCHIVED
    with pytest.raises(ProjectArchivedError):
        await h.container.toolset.resolve_toolset(p)


async def test_connecting_a_per_user_integration_refreshes_the_cached_auth_required_state():
    h = make_harness()
    cache = h.shared.toolset_cache
    key = cache.key(h.pid, "member:m", None)
    cache.put(key, "cached", cache.generation(h.pid))
    await h.shared.events.publish(ToolsetChanged(h.pid, "connection_stored"))
    assert cache.get(key) is None


# ====================================================================== concurrency cap
async def test_the_limiter_refuses_after_the_wait_and_releases_slots():
    limiter = ConcurrencyLimiter()
    first = await limiter.acquire("i", 1, 0.05)
    assert first is not None
    assert await limiter.acquire("i", 1, 0.05) is None  # full: refused after the bounded wait
    limiter.release(first)
    second = await limiter.acquire("i", 1, 0.05)
    assert second is not None  # regression: a released slot is reusable
    other = await limiter.acquire("other", 1, 0.05)
    assert other is not None  # keys are independent


async def test_a_busy_integration_returns_a_retryable_error_and_other_integrations_are_unaffected():
    h = make_harness()
    result, keys = await ready(h, [tool("a")])
    h.integrations.items[str(result.integration.id)].config["max_concurrent_calls"] = 1
    h.scripted.sleep = 0.3
    stage = next(s for s in h.container.gateway._stages if s.__class__.__name__ == "ExecuteStage")  # noqa: SLF001
    stage._concurrency_wait = 0.05  # noqa: SLF001
    slow = asyncio.create_task(h.container.gateway.invoke(req(h, "svc.a", {"q": "1"})))
    await asyncio.sleep(0.05)
    busy = await h.container.gateway.invoke(req(h, "svc.a", {"q": "2"}))
    assert busy.error_code == "integration_busy" and busy.retryable is True
    assert (await slow).ok is True


async def test_the_slot_is_released_when_the_call_fails():
    h = make_harness()
    result, _ = await ready(h, [tool("a")])
    h.integrations.items[str(result.integration.id)].config["max_concurrent_calls"] = 1
    h.scripted.raise_on_execute = RuntimeError("boom")
    for _ in range(3):  # would deadlock on the second call if the slot leaked
        outcome = await h.container.gateway.invoke(req(h, "svc.a", {"q": "x"}))
        assert outcome.error_code == "adapter_error"


async def test_invalid_concurrency_config_falls_back_to_the_default():
    h = make_harness()
    result, _ = await ready(h, [tool("a")])
    stage = next(s for s in h.container.gateway._stages if s.__class__.__name__ == "ExecuteStage")  # noqa: SLF001

    class T:
        config = {"max_concurrent_calls": True}

    assert concurrency_limit(T(), stage._default_concurrency) == stage._default_concurrency  # noqa: SLF001 - bool is not a valid limit
    T.config = {"max_concurrent_calls": 0}
    assert concurrency_limit(T(), stage._default_concurrency) == stage._default_concurrency  # noqa: SLF001
    T.config = {"max_concurrent_calls": 5}
    assert concurrency_limit(T(), stage._default_concurrency) == 5  # noqa: SLF001


def test_mcp_config_validates_max_concurrent_calls():
    adapter = McpAdapter(connector=None)  # type: ignore[arg-type]
    base = {"url": "https://x.example/mcp"}
    assert adapter.validate_config({**base, "max_concurrent_calls": 8})["max_concurrent_calls"] == 8
    assert "max_concurrent_calls" not in adapter.validate_config(base)
    for bad in (0, 257, True, "8"):
        with pytest.raises(BadRequestError):
            adapter.validate_config({**base, "max_concurrent_calls": bad})


# ====================================================================== performance targets
def p95(samples: List[float]) -> float:
    ordered = sorted(samples)
    return ordered[max(0, int(len(ordered) * 0.95) - 1)]


async def timed(fn, runs: int) -> List[float]:
    out = []
    for _ in range(runs):
        start = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - start) * 1000)
    return out


async def test_nfr_p1_a_cached_listing_of_500_tools_is_fast():
    h = make_harness()
    await ready(h, [tool(f"t{i}") for i in range(500)])
    p = principal(h)
    assert len((await h.container.toolset.resolve_toolset(p)).tools) == 500
    samples = await timed(lambda: h.container.toolset.resolve_toolset(p), 30)
    assert p95(samples) < 25, f"cached p95 {p95(samples):.1f} ms (target < 25 ms)"


async def test_nfr_p1_a_cold_listing_of_200_tools_stays_within_the_target():
    h = make_harness()
    await ready(h, [tool(f"t{i}") for i in range(200)])
    p = principal(h)
    samples = []
    for _ in range(10):
        h.shared.toolset_cache.invalidate_project(h.pid)
        start = time.perf_counter()
        await h.container.toolset.resolve_toolset(p)
        samples.append((time.perf_counter() - start) * 1000)
    # The in-memory fakes copy documents like a driver would, so this is an upper bound for the logic alone.
    assert p95(samples) < 150, f"cold p95 {p95(samples):.1f} ms"


async def test_nfr_p2_gateway_overhead_is_small():
    h = make_harness()
    await ready(h, [tool("a")])
    await h.container.gateway.invoke(req(h, "svc.a", {"q": "warm"}))
    samples = await timed(lambda: h.container.gateway.invoke(req(h, "svc.a", {"q": "x"})), 40)
    assert statistics.median(samples) < 15 and p95(samples) < 40, f"gateway p95 {p95(samples):.1f} ms (target < 15 ms)"


async def test_nfr_p4_discovery_of_200_tools_completes_well_inside_the_target():
    h = make_harness()
    start = time.perf_counter()
    await ready(h, [tool(f"t{i}") for i in range(200)])
    assert time.perf_counter() - start < 15


async def test_nfr_p5_many_concurrent_calls_all_complete_under_the_cap():
    h = make_harness()
    await ready(h, [tool("a")])
    h.scripted.sleep = 0.01
    results = await asyncio.gather(*(h.container.gateway.invoke(req(h, "svc.a", {"q": str(i)})) for i in range(60)))
    assert all(r.ok for r in results)
