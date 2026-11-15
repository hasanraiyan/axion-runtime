"""
Session pool against the **real official-SDK MCP server** (in-process, no sockets): proves the pool's ownership model works
with real anyio task groups, that pooling genuinely removes handshakes, and that auth, concurrency, idle expiry and shutdown
all behave with real sessions.
"""
import asyncio

import pytest

from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import UpstreamAuthError
from app.core.tools.types import ResolvedCredentials, Subject, SubjectType
from app.integrations.adapters import McpAdapter
from app.integrations.mcp_client import SdkMcpConnector
from app.integrations.mcp_pool import McpSessionPool, PooledMcpConnector
from tests.mcp_test_server import running_transport
from tests.test_mcp_adapter_sdk import make_integration, make_tool
from tests.tools_harness import StaticResolver

pytestmark = pytest.mark.usefixtures("tool_models")

BEARER = ResolvedCredentials(headers={"Authorization": "Bearer t"})


def build(transport, **pool_kwargs):
    pool = McpSessionPool(**pool_kwargs)
    inner = SdkMcpConnector(OutboundUrlGuard(StaticResolver()), inner_transport=transport)
    return pool, McpAdapter(PooledMcpConnector(inner, pool)), McpAdapter(inner)


async def run(adapter, i=0):
    result = await adapter.execute(make_integration(), make_tool("echo"), {"message": f"m{i}"}, BEARER, 10)
    assert not result.is_error and result.content[0].text == f"echo:m{i}"


async def test_pooling_removes_per_call_handshakes():
    async with running_transport(token="t") as (transport, gate):
        pool, pooled, plain = build(transport)
        before = len(gate.seen_hosts)
        for i in range(5):
            await run(plain, i)
        unpooled_requests = len(gate.seen_hosts) - before

        before = len(gate.seen_hosts)
        for i in range(5):
            await run(pooled, i)
        pooled_requests = len(gate.seen_hosts) - before

        assert pool.stats["opened"] == 1 and pool.stats["reused"] == 4
        # initialize + initialized + call + terminate per call, versus one handshake then one request per call.
        assert unpooled_requests >= 4 * 5 - 2 and pooled_requests <= 4 + 5
        await pool.close_all()


async def test_many_concurrent_calls_share_one_real_session():
    async with running_transport(token="t") as (transport, gate):
        pool, pooled, _ = build(transport)
        await asyncio.gather(*[run(pooled, i) for i in range(12)])
        assert pool.stats["opened"] == 1
        await pool.close_all()


async def test_listing_and_discovery_use_the_same_pooled_session():
    async with running_transport(token="t", extras=True) as (transport, gate):
        pool, pooled, _ = build(transport)
        integration = make_integration()
        assert {t.name for t in await pooled.discover(integration, BEARER)} >= {"echo", "show_chart", "refresh_chart"}
        assert [p.name for p in await pooled.list_prompts(integration, BEARER)] == ["summarize"]
        assert len(await pooled.list_resources(integration, BEARER)) == 2
        await run(pooled)
        assert pool.stats["opened"] == 1 and pool.stats["reused"] == 3
        await pool.close_all()


async def test_a_rejected_credential_is_classified_and_never_pooled_for_later_good_credentials():
    async with running_transport(token="t") as (transport, gate):
        pool, pooled, _ = build(transport)
        bad = ResolvedCredentials(headers={"Authorization": "Bearer wrong"})
        probe = await pooled.probe(make_integration(), bad)
        assert not probe.healthy and probe.status == "auth_failed"
        assert pool.size() == 0  # an entry that never opened leaves nothing behind

        await run(pooled)  # the good credential opens its own, different session
        with pytest.raises(UpstreamAuthError):
            await pooled.discover(make_integration(), bad)
        assert pool.size() == 1
        await pool.close_all()


async def test_idle_real_sessions_close_cleanly_and_reopen():
    async with running_transport(token="t") as (transport, gate):
        pool, pooled, _ = build(transport, idle_ttl=0.2)
        await run(pooled)
        await asyncio.sleep(0.6)
        assert pool.size() == 0 and pool.stats["idle_closed"] == 1
        await run(pooled)  # a fresh session after the idle close
        assert pool.stats["opened"] == 2
        await pool.close_all()


async def test_eviction_and_shutdown_close_real_sessions_without_task_errors():
    async with running_transport(token="t") as (transport, gate):
        from beanie import PydanticObjectId

        pool, pooled, _ = build(transport)
        mine, other = make_integration(), make_integration()
        mine.id, other.id = PydanticObjectId(), PydanticObjectId()  # unsaved documents have no id; give each its own
        await pooled.probe(mine, BEARER)
        await pooled.probe(other, BEARER)
        assert pool.size() == 2

        assert await pool.evict_integration(str(mine.id)) == 1 and pool.size() == 1  # only the named integration
        await pooled.probe(mine, BEARER)  # and it reopens afterwards
        assert pool.size() == 2
        await pool.close_all()
        assert pool.size() == 0  # no "cancel scope in a different task" errors from the SDK's anyio groups


async def test_pooled_sessions_flow_through_the_gateway():
    """A full tool call (authorization, validation, credentials, execution) reuses the pooled session."""
    from app.models.integration import IntegrationType
    from app.schemas.tools import BindingReplaceRequest, BindingRule, IntegrationCreateRequest, ToolSettingUpdateRequest
    from app.models.tool import BindingSubjectType, BindingTargetType
    from app.core.tools.types import Actor, ActorType, InvocationRequest, PrincipalContext
    from tests.mcp_test_server import URL
    from tests.tools_harness import make_harness

    async with running_transport(extras=True) as (transport, gate):
        pool = McpSessionPool()
        inner = SdkMcpConnector(OutboundUrlGuard(StaticResolver()), inner_transport=transport)
        h = make_harness(connector=PooledMcpConnector(inner, pool))
        result = await h.container.onboarding.create_and_verify(
            h.project.id, IntegrationCreateRequest(type=IntegrationType.MCP, slug="remote", name="Remote", config={"url": URL}), "user_admin"
        )
        _, setting = await h.container.catalog.get_tool(h.project.id, "remote.echo")
        await h.container.tool_settings.update(h.project.id, "remote.echo", ToolSettingUpdateRequest(revision=setting.revision, is_enabled=True), "user_admin")
        await h.container.bindings.replace(
            h.project.id,
            BindingReplaceRequest(subject_type=BindingSubjectType.PROJECT_DEFAULT, bindings=[BindingRule(target_type=BindingTargetType.INTEGRATION, target_id=str(result.integration.id))]),
            "user_admin",
        )
        member = Subject(SubjectType.MEMBER, id="m")
        principal = PrincipalContext(project_id=h.pid, actor=Actor(ActorType.USER, "m"), subject=member)
        opened_before = pool.stats["opened"]
        for i in range(4):
            r = await h.container.gateway.invoke(InvocationRequest(project_id=h.pid, tool_key="remote.echo", arguments={"message": f"g{i}"}, principal=principal))
            assert r.ok and f"echo:g{i}" in r.content[0].text
        assert pool.stats["opened"] - opened_before <= 1  # four gateway calls shared a single session
        await pool.close_all()
