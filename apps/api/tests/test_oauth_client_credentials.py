"""
OAuth client credentials (machine-to-machine) integrations (SRS-07 FR-24).

Runs against the in-process authorization server's ``client_credentials`` grant, with the real SDK MCP server behind it.
The fake secret store decrypts a secret named ``X`` to ``plain:X``, so the client secret here is ``plain:SVC_SECRET``.
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import pytest
from beanie import PydanticObjectId

from app.core.exceptions import BadRequestError, UrlBlockedError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import OAuthFlowFailed, UpstreamAuthError
from app.core.tools.oauth import TokenSet
from app.core.tools.token_cache import TokenCache
from app.core.tools.types import Subject, SubjectType
from app.integrations.auth import OAuthClientCredentialsStrategy, build_default_auth_registry
from app.integrations.mcp_client import SdkMcpConnector
from app.integrations.oauth import OAuthFlowClient
from app.models.integration import AuthProfile, AuthType, CredentialMode, IntegrationStatus, IntegrationType
from app.schemas.tools import IntegrationCreateRequest
from tests.oauth_test_server import RESOURCE, OAuthMcpServer
from tests.test_tools_connections import ADMIN, Env
from tests.tools_harness import StaticResolver, make_harness, tool

pytestmark = pytest.mark.usefixtures("tool_models")

TOKEN_ENDPOINT = "https://mcp.example.com/token"
CLIENT_ID = "svc-client"
SECRET = "plain:SVC_SECRET"
MEMBER = Subject(SubjectType.MEMBER, id="user_member")
SID = PydanticObjectId()


def profile(secret_id: Any, **oauth: Any) -> AuthProfile:
    base = {"client_id": CLIENT_ID, "token_endpoint": TOKEN_ENDPOINT, "scopes": ["read"]}
    base.update(oauth)
    return AuthProfile(auth_type=AuthType.OAUTH_CLIENT_CREDENTIALS, credential_mode=CredentialMode.PROJECT_SHARED, secret_id=secret_id, oauth=base)


@asynccontextmanager
async def env() -> AsyncIterator[Env]:
    server = OAuthMcpServer()
    server.confidential_clients[CLIENT_ID] = SECRET
    async with server.running():
        guard = OutboundUrlGuard(StaticResolver())
        h = make_harness(
            connector=SdkMcpConnector(guard, inner_transport=server.transport),
            oauth=OAuthFlowClient(guard, inner_transport=server.transport),
        )
        yield Env(h, server)


async def create(e: Env, **oauth: Any):
    secret = e.h.secrets.add(e.h.project.id, "SVC_SECRET")
    created = await e.c.integrations.create(
        e.h.project.id,
        IntegrationCreateRequest(type=IntegrationType.MCP, slug="remote", name="Remote", config={"url": RESOURCE}, auth_profile=profile(secret.id, **oauth)),
        ADMIN,
    )
    e.integration_id = str(created.id)
    return created, secret


async def ready(e: Env) -> str:
    created, _ = await create(e)
    await e.c.onboarding.verify(e.h.project.id, e.integration_id, ADMIN)
    return await e.enable_and_bind()


# ====================================================================== end to end
async def test_a_client_credentials_integration_verifies_discovers_and_serves_tools():
    async with env() as e:
        key = await ready(e)
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.ACTIVE
        result = await e.invoke(key, MEMBER)
        assert result.ok and "echo:hi" in result.content[0].text
        assert e.server.tokens_used_by(f"client:{CLIENT_ID}")  # the machine token reached the MCP server


async def test_the_token_is_reused_across_calls_and_not_fetched_each_time():
    async with env() as e:
        key = await ready(e)
        before = e.server.counters["client_credentials"]
        for _ in range(5):
            assert (await e.invoke(key, MEMBER)).ok
        assert e.server.counters["client_credentials"] - before <= 1  # at most the first fetch after verify


async def test_concurrent_first_calls_share_one_token_request():
    async with env() as e:
        key = await ready(e)
        e.h.shared.token_cache._entries.clear()  # noqa: SLF001
        e.server.cc_delay = 0.1
        before = e.server.counters["client_credentials"]
        results = await asyncio.gather(*(e.invoke(key, MEMBER) for _ in range(8)))
        assert all(r.ok for r in results)
        assert e.server.counters["client_credentials"] - before == 1  # single flight


async def test_scope_and_basic_auth_are_sent_to_the_token_endpoint():
    async with env() as e:
        await ready(e)
        first = e.server.cc_requests[0]
        assert first["method"] == "client_secret_basic" and first["form"]["scope"] == "read"
        assert "client_secret" not in first["form"]  # the secret travels only in the Authorization header


async def test_post_authentication_puts_the_secret_in_the_body():
    async with env() as e:
        await create(e, token_endpoint_auth_method="client_secret_post")
        await e.c.onboarding.verify(e.h.project.id, e.integration_id, ADMIN)
        assert e.server.cc_requests[0]["method"] == "client_secret_post"


async def test_wrong_client_secret_fails_verification_without_leaking_it():
    async with env() as e:
        e.server.confidential_clients[CLIENT_ID] = "something-else"
        await create(e)
        outcome = await e.c.onboarding.verify(e.h.project.id, e.integration_id, ADMIN)
        assert SECRET not in repr(outcome)
        integration = await e.c.integrations.get(e.h.project.id, e.integration_id)
        assert integration.status != IntegrationStatus.ACTIVE


async def test_a_rejected_client_returns_a_clear_error_to_the_agent_not_misconfiguration():
    async with env() as e:
        key = await ready(e)
        e.h.shared.token_cache._entries.clear()  # noqa: SLF001
        e.server.confidential_clients[CLIENT_ID] = "rotated-upstream"
        result = await e.invoke(key, MEMBER)
        assert not result.ok and result.error_code == "upstream_auth_failed"


async def test_a_revoked_cached_token_is_replaced_and_the_call_is_retried_once():
    async with env() as e:
        key = await ready(e)
        assert (await e.invoke(key, MEMBER)).ok
        for info in e.server.access.values():
            info["revoked"] = True  # the upstream revokes everything issued so far
        before = e.server.counters["client_credentials"]
        assert (await e.invoke(key, MEMBER)).ok  # transparently retried with a fresh token
        assert e.server.counters["client_credentials"] - before == 1
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.ACTIVE


async def test_credentials_rejected_even_when_fresh_mark_the_integration_failing_after_one_retry():
    async with env() as e:
        key = await ready(e)
        assert (await e.invoke(key, MEMBER)).ok
        e.server.confidential_clients[CLIENT_ID] = "rotated-upstream"  # the fresh token cannot be obtained
        for info in e.server.access.values():
            info["revoked"] = True
        before = e.server.counters["client_credentials"]
        result = await e.invoke(key, MEMBER)
        assert not result.ok and result.error_code == "upstream_auth_failed"
        assert e.server.counters["client_credentials"] - before == 1  # exactly one retry, no loop
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status != IntegrationStatus.ACTIVE


async def test_a_fresh_token_that_is_also_rejected_fails_cleanly_after_exactly_one_retry():
    async with env() as e:
        key = await ready(e)
        assert (await e.invoke(key, MEMBER)).ok
        e.server.cc_revoke_on_issue = True  # the upstream rejects even freshly issued tokens
        for info in e.server.access.values():
            info["revoked"] = True
        before = e.server.counters["client_credentials"]
        result = await e.invoke(key, MEMBER)
        assert result.error_code == "upstream_auth_failed"  # not an internal error from the retry loop
        assert e.server.counters["client_credentials"] - before == 1


async def test_static_credentials_are_never_retried_on_rejection():
    h = make_harness()
    from tests.test_tools_services import ready as ready_scripted, req as scripted_req

    await ready_scripted(h, [tool("a")])
    attempts = []
    original = h.scripted.execute

    async def counting(*args, **kwargs):
        attempts.append(1)
        return await original(*args, **kwargs)

    h.scripted.execute = counting  # type: ignore[method-assign]
    h.scripted.raise_on_execute = UpstreamAuthError("no")
    result = await h.container.gateway.invoke(scripted_req(h, "svc.a", {"q": "x"}))
    assert result.error_code == "upstream_auth_failed" and len(attempts) == 1


async def test_rotating_the_client_secret_takes_effect_immediately():
    async with env() as e:
        key = await ready(e)
        assert (await e.invoke(key, MEMBER)).ok
        secret = next(iter(e.h.secrets.secrets.values()))
        secret.name = "SVC_SECRET_V2"  # the fake store derives the value from the name
        e.server.confidential_clients[CLIENT_ID] = "plain:SVC_SECRET_V2"
        assert (await e.invoke(key, MEMBER)).ok  # a cached token minted with the old secret is not reused
        assert e.server.cc_requests[-1]["client_id"] == CLIENT_ID and e.server.counters["client_credentials"] >= 2


# ====================================================================== validation
async def test_creation_requires_a_secret_a_client_id_and_an_https_token_endpoint():
    async with env() as e:
        secret = e.h.secrets.add(e.h.project.id, "SVC_SECRET")

        async def attempt(auth: AuthProfile):
            return await e.c.integrations.create(
                e.h.project.id,
                IntegrationCreateRequest(type=IntegrationType.MCP, slug="svc_x", name="Svc X", config={"url": RESOURCE}, auth_profile=auth),
                ADMIN,
            )

        with pytest.raises(BadRequestError):
            await attempt(profile(None))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, client_id=""))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, token_endpoint="http://mcp.example.com/token"))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, token_endpoint="https://user:pw@mcp.example.com/token"))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, surprise="x"))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, token_endpoint_auth_method="none"))
        with pytest.raises(BadRequestError):
            await attempt(profile(secret.id, scopes="read"))
        per_user = profile(secret.id)
        per_user.credential_mode = CredentialMode.PER_USER
        with pytest.raises(BadRequestError):
            await attempt(per_user)


async def test_the_token_endpoint_is_checked_by_the_outbound_guard_on_save():
    async with env() as e:
        secret = e.h.secrets.add(e.h.project.id, "SVC_SECRET")
        with pytest.raises(UrlBlockedError):
            await e.c.integrations.create(
                e.h.project.id,
                IntegrationCreateRequest(
                    type=IntegrationType.MCP, slug="svc_x", name="Svc X", config={"url": RESOURCE},
                    auth_profile=profile(secret.id, token_endpoint="https://127.0.0.1/token"),
                ),
                ADMIN,
            )


async def test_the_token_endpoint_may_live_on_a_host_outside_the_mcp_allow_list():
    async with env() as e:
        secret = e.h.secrets.add(e.h.project.id, "SVC_SECRET")
        await e.c.integrations.create(
            e.h.project.id,
            IntegrationCreateRequest(
                type=IntegrationType.MCP, slug="svc_x", name="Svc X", config={"url": RESOURCE, "allowed_hosts": ["mcp.example.com"]},
                auth_profile=profile(secret.id, token_endpoint="https://login.example.org/token"),
            ),
            ADMIN,
        )


def test_the_strategy_is_only_registered_when_a_token_flow_is_available():
    assert AuthType.OAUTH_CLIENT_CREDENTIALS not in build_default_auth_registry().types()

    class Flow:
        async def client_credentials(self, *a: Any) -> TokenSet:
            return TokenSet("t")

    assert AuthType.OAUTH_CLIENT_CREDENTIALS in build_default_auth_registry(Flow()).types()  # type: ignore[arg-type]


# ====================================================================== token cache and mapping
class CountingFlow:
    def __init__(self, expires_in: Optional[int] = 3600, error: Optional[Exception] = None) -> None:
        self.calls = 0
        self.expires_in = expires_in
        self.error = error

    async def client_credentials(self, *args: Any) -> TokenSet:
        self.calls += 1
        if self.error:
            raise self.error
        return TokenSet(f"token-{self.calls}", expires_in=self.expires_in)


class Secrets:
    async def read(self, project_id: str, secret_id: str) -> str:
        return "s"


def strategy(flow: CountingFlow, now: list) -> OAuthClientCredentialsStrategy:
    return OAuthClientCredentialsStrategy(flow, TokenCache(clock=lambda: now[0]))  # type: ignore[arg-type]


async def test_a_token_is_refetched_shortly_before_it_expires():
    flow, now = CountingFlow(expires_in=3600), [0.0]
    s, p = strategy(flow, now), profile(SID)
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    now[0] = 3500  # inside the 60 s skew window? no: 3600 - 60 = 3540
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    assert flow.calls == 1
    now[0] = 3541
    creds = await s.build("p", p, Secrets())  # type: ignore[arg-type]
    assert flow.calls == 2 and creds.headers["Authorization"] == "Bearer token-2"


async def test_a_token_without_expires_in_is_cached_only_briefly():
    flow, now = CountingFlow(expires_in=None), [0.0]
    s, p = strategy(flow, now), profile(SID)
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    now[0] = 200
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    assert flow.calls == 1
    now[0] = 241  # default 300 s life minus the 60 s skew
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    assert flow.calls == 2


async def test_a_token_too_short_lived_to_reuse_is_never_cached():
    flow, now = CountingFlow(expires_in=30), [0.0]
    s, p = strategy(flow, now), profile(SID)
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    await s.build("p", p, Secrets())  # type: ignore[arg-type]
    assert flow.calls == 2


async def test_projects_and_clients_never_share_cached_tokens():
    flow, now = CountingFlow(), [0.0]
    s = strategy(flow, now)
    await s.build("p1", profile(SID), Secrets())  # type: ignore[arg-type]
    await s.build("p2", profile(SID), Secrets())  # type: ignore[arg-type]
    await s.build("p1", profile(SID, client_id="other"), Secrets())  # type: ignore[arg-type]
    assert flow.calls == 3


async def test_flow_failures_map_to_neutral_upstream_errors_and_are_not_cached():
    from app.core.tools.errors import OAuthInvalidClient, UpstreamError

    now = [0.0]
    rejected = strategy(CountingFlow(error=OAuthInvalidClient("no")), now)
    with pytest.raises(UpstreamAuthError):
        await rejected.build("p", profile(SID), Secrets())  # type: ignore[arg-type]
    flaky = CountingFlow(error=OAuthFlowFailed("Token endpoint returned HTTP 503"))
    s = strategy(flaky, now)
    with pytest.raises(UpstreamError) as caught:
        await s.build("p", profile(SID), Secrets())  # type: ignore[arg-type]
    assert not isinstance(caught.value, UpstreamAuthError)
    flaky.error = None
    assert (await s.build("p", profile(SID), Secrets())).headers  # type: ignore[arg-type]  # a failure is not remembered


def test_the_strategy_itself_rejects_insecure_and_credentialed_token_endpoints():
    """Independent of the Outbound Guard (defence in depth): the profile is invalid on its own."""
    s = OAuthClientCredentialsStrategy(CountingFlow())  # type: ignore[arg-type]
    s.validate(profile(SID))
    for bad in ("http://mcp.example.com/token", "https://user:pw@mcp.example.com/token", "https://mcp.example.com/token#frag", "ftp://x/y", ""):
        with pytest.raises(BadRequestError):
            s.validate(profile(SID, token_endpoint=bad))
