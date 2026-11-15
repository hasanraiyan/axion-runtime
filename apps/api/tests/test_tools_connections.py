"""
Phase 2 tests (SRS-07 FR-24..FR-29, FR-71..FR-83): OAuth connect flow, per-user connections for members and
end users, token refresh and dead grants, subject isolation, single-use links, return-URL allow-list.

OAuth runs against a real in-process authorization server (``oauth_test_server``): the actual SDK discovery and
registration helpers, real PKCE verification, rotating refresh tokens, and an OAuth-protected official-SDK MCP
server. No sockets and no network.
"""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, List, Optional

import pytest
from beanie import PydanticObjectId

from app.core.exceptions import BadRequestError, CryptographicIntegrityError as CryptoError, ForbiddenError, NotFoundError
from app.core.outbound import OutboundUrlGuard
from app.core.tools.types import InvocationRequest, ProbeResult, Subject, SubjectType
from app.integrations.mcp_client import SdkMcpConnector
from app.integrations.oauth import OAuthFlowClient
from app.models.connection import ConnectionStatus
from app.models.integration import AuthProfile, AuthType, CredentialMode, EndUserAccess, IntegrationStatus, IntegrationType
from app.models.tool import Audience, BindingSubjectType, BindingTargetType
from app.models.tool_invocation import InvocationStatus
from app.schemas.tools import (
    BindingReplaceRequest,
    BindingRule,
    ConnectionResponse,
    IntegrationCreateRequest,
    ToolSettingUpdateRequest,
)
from app.services.tools.credentials import AuthRequired
from tests.oauth_test_server import RESOURCE, OAuthMcpServer
from tests.tools_harness import Harness, StaticResolver, make_harness, tool

pytestmark = pytest.mark.usefixtures("tool_models")

ADMIN = "user_admin"
ADMIN_SUBJECT = Subject(SubjectType.MEMBER, id=ADMIN)
PROJECT = Subject(SubjectType.PROJECT)
APP_ORIGIN = "https://app.example.com"


@dataclass
class Env:
    h: Harness
    server: OAuthMcpServer
    integration_id: str = ""

    @property
    def c(self):
        return self.h.container

    async def create(self, mode: CredentialMode, scopes: Optional[List[str]] = None, **profile: Any) -> str:
        oauth = {"scopes": scopes if scopes is not None else ["read"], **profile.pop("oauth", {})}
        created = await self.c.integrations.create(
            self.h.project.id,
            IntegrationCreateRequest(
                type=IntegrationType.MCP, slug="remote", name="Remote", config={"url": RESOURCE},
                auth_profile=AuthProfile(auth_type=AuthType.OAUTH_AUTHORIZATION_CODE, credential_mode=mode, oauth=oauth, **profile),
            ),
            ADMIN,
        )
        self.integration_id = str(created.id)
        return self.integration_id

    async def end_user(self, external_id: str) -> Subject:
        return await self.c.end_users.resolve_subject(self.h.project.id, external_id, "machine")

    async def authorize(self, subject: Subject, user_label: str, return_url: Optional[str] = None):
        """Start a flow and play the browser; returns (authorization_url, redirect_params)."""
        self.server.next_user = user_label
        url = await self.c.connect_flow.start_authorization(self.h.project.id, self.integration_id, subject, return_url, ADMIN)
        return url, await self.server.browser_authorize(url)

    async def connect(self, subject: Subject, user_label: str, return_url: Optional[str] = None):
        _, params = await self.authorize(subject, user_label, return_url)
        return await self.c.connect_flow.complete(params.get("state"), params.get("code"), params.get("error"), params.get("iss"))

    async def enable_and_bind(self, audience: Optional[List[Audience]] = None, tool_name: str = "echo") -> str:
        key = f"remote.{tool_name}"
        _, setting = await self.c.catalog.get_tool(self.h.project.id, key)
        await self.c.tool_settings.update(self.h.project.id, key, ToolSettingUpdateRequest(revision=setting.revision, is_enabled=True), ADMIN)
        await self.c.bindings.replace(
            self.h.project.id,
            BindingReplaceRequest(
                subject_type=BindingSubjectType.PROJECT_DEFAULT, audience=audience or [Audience.MEMBERS, Audience.END_USERS],
                bindings=[BindingRule(target_type=BindingTargetType.INTEGRATION, target_id=self.integration_id)],
            ),
            ADMIN,
        )
        return key

    async def open_to_end_users(self) -> None:
        await self.c.integrations.set_end_user_access(self.h.project.id, self.integration_id, EndUserAccess.OPEN, True, ADMIN)

    async def enable_policy(self, origins: Optional[List[str]] = None) -> None:
        policy = await self.c.policy.get(self.h.project.id)
        await self.c.policy.update(
            self.h.project.id, policy.revision, ADMIN, allowed_return_origins=origins or [APP_ORIGIN], end_user_connect_enabled=True
        )

    def invoke(self, key: str, subject: Subject, args: Optional[dict] = None):
        from app.core.tools.types import Actor, ActorType, PrincipalContext

        principal = PrincipalContext(
            project_id=self.h.pid, actor=Actor(ActorType.MACHINE if subject.type != SubjectType.MEMBER else ActorType.USER, subject.id or "m"),
            subject=subject, origin="runtime",
        )
        return self.c.gateway.invoke(InvocationRequest(project_id=self.h.pid, tool_key=key, arguments=args if args is not None else {"message": "hi"}, principal=principal))

    def stored(self, subject: Subject):
        return next(c for c in self.h.connections_repo.items.values() if c.subject_key == subject.key)

    def expire(self, subject: Subject) -> None:
        self.stored(subject).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)


@asynccontextmanager
async def env() -> AsyncIterator[Env]:
    server = OAuthMcpServer()
    async with server.running():
        guard = OutboundUrlGuard(StaticResolver())
        h = make_harness(
            connector=SdkMcpConnector(guard, inner_transport=server.transport),
            oauth=OAuthFlowClient(guard, inner_transport=server.transport),
        )
        yield Env(h, server)


# ====================================================================== project (shared) OAuth
async def test_shared_oauth_connects_discovers_and_serves_tools():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.DRAFT

        url, params = await e.authorize(PROJECT, "service-account")
        assert "code_challenge_method=S256" in url and "resource=" in url and "state=" in url and "scope=read" in url
        outcome = await e.c.connect_flow.complete(params["state"], params["code"])
        assert outcome.success and outcome.integration_slug == "remote"

        integration = await e.c.integrations.get(e.h.project.id, e.integration_id)
        assert integration.status == IntegrationStatus.ACTIVE  # verified and discovered by the post-connect hook
        assert sorted(d.tool_key for d in e.h.tools_repo.items.values()) == [
            "remote.delete_everything", "remote.echo", "remote.explode", "remote.show_chart"
        ]
        key = await e.enable_and_bind()
        member = Subject(SubjectType.MEMBER, id="user_member")
        result = await e.invoke(key, member)
        assert result.ok and "echo:hi" in result.content[0].text
        assert e.server.tokens_used_by("service-account")  # the project's own credential was used


async def test_stored_tokens_are_encrypted_and_never_returned():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        connection = e.stored(PROJECT)
        access_token = next(iter(e.server.access))
        dumped = connection.model_dump_json()
        assert access_token not in dumped and "refresh" not in dumped.replace("refresh_envelope", "")
        response = ConnectionResponse.from_model(connection).model_dump_json()
        assert access_token not in response and "envelope" not in response.lower()


async def test_dynamic_client_registration_happens_once_and_is_reused():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        await e.connect(PROJECT, "svc")  # reconnect
        assert e.server.counters["registrations"] == 1
        client = next(iter(e.h.oauth_clients.items.values()))
        assert client.dynamically_registered and client.client_secret_envelope is None and client.token_endpoint_auth_method == "none"


async def test_manual_client_uses_the_project_secret_and_skips_registration():
    async with env() as e:
        secret = e.h.secrets.add(e.h.project.id, "OAUTH_CLIENT_SECRET")
        await e.create(CredentialMode.PROJECT_SHARED, oauth={"client_id": "manual-1"}, secret_id=secret.id)
        url = await e.c.connect_flow.start_authorization(e.h.project.id, e.integration_id, PROJECT, None, ADMIN)
        assert "client_id=manual-1" in url and e.server.counters["registrations"] == 0
        client = next(iter(e.h.oauth_clients.items.values()))
        assert not client.dynamically_registered and client.token_endpoint_auth_method == "client_secret_basic"
        assert client.client_secret_envelope is not None and "plain:" not in client.model_dump_json()  # sealed, not the raw secret


# ====================================================================== flow security
async def test_a_callback_cannot_be_replayed_and_unknown_state_is_rejected():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        _, params = await e.authorize(PROJECT, "svc")
        first = await e.c.connect_flow.complete(params["state"], params["code"])
        again = await e.c.connect_flow.complete(params["state"], params["code"])
        assert first.success and not again.success and again.error == "connect_session_expired"
        assert (await e.c.connect_flow.complete("not-a-real-state", "x")).error == "unknown_state"
        assert (await e.c.connect_flow.complete(None, "x")).error == "invalid_request"


async def test_a_link_is_single_use_and_expires():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        ann = await e.end_user("cust_ann")
        url, _ = await e.c.connect_flow.create_link(e.h.project.id, e.integration_id, ann, f"{APP_ORIGIN}/done", ADMIN)
        token = url.rsplit("/", 1)[1]
        assert url.startswith("https://api.axion.test/api/v1/integrations/connect/")

        first = await e.c.connect_flow.begin(token)
        assert first.startswith("https://mcp.example.com/authorize?")
        with pytest.raises(BadRequestError) as exc:
            await e.c.connect_flow.begin(token)  # the link is dead after its first use
        assert exc.value.code == "CONNECT_SESSION_EXPIRED"

        url2, _ = await e.c.connect_flow.create_link(e.h.project.id, e.integration_id, ann, None, ADMIN)
        session = next(s for s in e.h.sessions.items.values() if s.status.value == "pending")
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(BadRequestError):
            await e.c.connect_flow.begin(url2.rsplit("/", 1)[1])


async def test_link_secrets_are_stored_only_as_hashes():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        url, _ = await e.c.connect_flow.create_link(e.h.project.id, e.integration_id, await e.end_user("cust_ann"), None, ADMIN)
        token = url.rsplit("/", 1)[1]
        stored = [s.model_dump_json() for s in e.h.sessions.items.values()]
        assert stored and all(token not in s for s in stored)


async def test_provider_denial_creates_no_connection():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        e.server.deny_authorization = True
        outcome = await e.connect(PROJECT, "svc")
        assert not outcome.success and outcome.error == "access_denied" and not e.h.connections_repo.items


async def test_code_substitution_is_defeated_by_pkce():
    """A code issued for session A cannot be redeemed through session B: the verifier will not match."""
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        _, a = await e.authorize(PROJECT, "svc")
        _, b = await e.authorize(PROJECT, "attacker")
        outcome = await e.c.connect_flow.complete(b["state"], a["code"])
        assert not outcome.success and outcome.error == "token_exchange_failed" and not e.h.connections_repo.items


async def test_issuer_mismatch_and_missing_issuer_are_rejected():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        e.server.advertise_iss = True
        e.server.iss_value = "https://evil.example.com"
        bad = await e.connect(PROJECT, "svc")
        assert not bad.success and bad.error == "token_exchange_failed"

        e.server.iss_value = "https://mcp.example.com"
        _, params = await e.authorize(PROJECT, "svc")
        missing = await e.c.connect_flow.complete(params["state"], params["code"], iss=None)  # advertised, so required
        assert not missing.success
        _, ok_params = await e.authorize(PROJECT, "svc")
        assert (await e.c.connect_flow.complete(ok_params["state"], ok_params["code"], iss=ok_params["iss"])).success


async def test_redirect_target_carries_only_an_outcome_never_tokens_or_codes():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        outcome = await e.connect(await e.end_user("cust_ann"), "ann", return_url=f"{APP_ORIGIN}/settings?tab=apps")
        target = outcome.redirect_target()
        assert target.startswith(f"{APP_ORIGIN}/settings?tab=apps&status=success&integration=remote")
        assert "code=" not in target and "token" not in target and "state" not in target


# ====================================================================== return URL allow-list & policy
async def test_return_urls_must_match_an_allowed_origin_exactly():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy([APP_ORIGIN])
        ann = await e.end_user("cust_ann")

        async def link(url):
            return await e.c.connect_flow.create_link(e.h.project.id, e.integration_id, ann, url, ADMIN)

        await link(f"{APP_ORIGIN}/ok")
        for evil in (
            "https://evil.example.com/x", "https://app.example.com.evil.com/", "http://app.example.com/x",
            "https://app.example.com@evil.com/", "javascript:alert(1)", "//evil.com", "https://app.example.com:8443/x",
        ):
            with pytest.raises(BadRequestError) as exc:
                await link(evil)
            assert exc.value.code in ("RETURN_URL_NOT_ALLOWED", "BAD_REQUEST"), evil


async def test_policy_rejects_wildcard_and_insecure_origins_and_stale_revisions():
    async with env() as e:
        policy = await e.c.policy.get(e.h.project.id)
        for bad in (["*"], ["https://*.example.com"], ["http://example.com"], ["ftp://example.com"], ["https://user:pw@example.com"]):
            with pytest.raises(BadRequestError):
                await e.c.policy.update(e.h.project.id, policy.revision, ADMIN, allowed_return_origins=bad)
        updated = await e.c.policy.update(e.h.project.id, policy.revision, ADMIN, allowed_return_origins=["https://App.Example.com/path"], end_user_connect_enabled=True)
        assert updated.allowed_return_origins == [APP_ORIGIN]  # normalized to an origin
        from app.core.exceptions import RevisionConflictError

        with pytest.raises(RevisionConflictError):
            await e.c.policy.update(e.h.project.id, policy.revision, ADMIN, end_user_connect_enabled=False)
        local = await e.c.policy.update(e.h.project.id, updated.revision, ADMIN, allowed_return_origins=["http://localhost:3000"])
        assert local.allowed_return_origins == ["http://localhost:3000"]


async def test_end_user_connections_are_off_until_the_project_enables_them():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        ann = await e.end_user("cust_ann")
        with pytest.raises(ForbiddenError) as exc:
            await e.c.connect_flow.start_authorization(e.h.project.id, e.integration_id, ann, None, ADMIN)
        assert exc.value.code == "END_USER_CONNECT_DISABLED"
        with pytest.raises(ForbiddenError):
            await e.c.connect_flow.create_link(e.h.project.id, e.integration_id, ann, None, ADMIN)
        await e.enable_policy()
        assert (await e.connect(ann, "ann")).success


async def test_subject_kind_must_match_the_credential_mode():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        with pytest.raises(BadRequestError):  # nobody can connect the project's credential for a per-user integration
            await e.c.connect_flow.start_authorization(e.h.project.id, e.integration_id, PROJECT, None, ADMIN)

    async with env() as e2:
        await e2.create(CredentialMode.PROJECT_SHARED)
        await e2.enable_policy()
        with pytest.raises(BadRequestError):  # end users cannot connect a project-shared integration
            await e2.c.connect_flow.start_authorization(e2.h.project.id, e2.integration_id, await e2.end_user("cust_ann"), None, ADMIN)


# ====================================================================== per-user connections
async def test_each_user_connects_their_own_account_and_never_uses_anothers():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        # An admin connects their own member account, which is what lets them discover the tools.
        assert (await e.connect(ADMIN_SUBJECT, "admin")).success
        await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        key = await e.enable_and_bind()
        await e.open_to_end_users()

        ann, bob = await e.end_user("cust_ann"), await e.end_user("cust_bob")
        assert (await e.connect(ann, "ann")).success and (await e.connect(bob, "bob")).success

        assert (await e.invoke(key, ann)).ok and (await e.invoke(key, bob)).ok
        ann_tokens, bob_tokens = e.server.tokens_used_by("ann"), e.server.tokens_used_by("bob")
        assert ann_tokens and bob_tokens and not set(ann_tokens) & set(bob_tokens)
        # Every request made on Ann's behalf carried Ann's token (and only Ann's): no cross-subject use.
        for request in e.server.mcp_requests:
            assert request["user"] in ("admin", "ann", "bob")
        assert e.server.tokens_used_by("alice") == []


async def test_per_user_integrations_report_auth_required_and_never_fall_back():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        assert (await e.connect(ADMIN_SUBJECT, "admin")).success
        await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        key = await e.enable_and_bind()
        await e.open_to_end_users()
        ann, bob = await e.end_user("cust_ann"), await e.end_user("cust_bob")

        from app.core.tools.types import Actor, ActorType, PrincipalContext

        def principal(subject):
            return PrincipalContext(project_id=e.h.pid, actor=Actor(ActorType.MACHINE, "m"), subject=subject)

        before = await e.c.toolset.resolve_toolset(principal(ann))
        assert before.tools == [] and [a.integration for a in before.auth_required] == ["remote"] and before.auth_required[0].connect_available
        refused = await e.invoke(key, ann)
        assert refused.status == InvocationStatus.AUTH_REQUIRED

        await e.connect(ann, "ann")
        assert [t.tool_key for t in (await e.c.toolset.resolve_toolset(principal(ann))).tools] == [key]
        # Bob has not connected: Ann's and the admin's connections must not make the tool work for him.
        assert (await e.c.toolset.resolve_toolset(principal(bob))).tools == []
        assert (await e.invoke(key, bob)).status == InvocationStatus.AUTH_REQUIRED
        assert e.server.tokens_used_by("bob") == []


async def test_connect_available_follows_the_project_policy_for_end_users():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        assert (await e.connect(ADMIN_SUBJECT, "admin")).success
        await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        await e.enable_and_bind()
        await e.open_to_end_users()
        from app.core.tools.types import Actor, ActorType, PrincipalContext

        ann = await e.end_user("cust_ann")
        toolset = await e.c.toolset.resolve_toolset(PrincipalContext(project_id=e.h.pid, actor=Actor(ActorType.MACHINE, "m"), subject=ann))
        assert toolset.auth_required[0].connect_available is False  # policy has not enabled end-user connect


async def test_connection_ciphertext_is_bound_to_its_subject_integration_and_project():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        ann, bob = await e.end_user("cust_ann"), await e.end_user("cust_bob")
        await e.connect(ann, "ann")
        envelope = e.stored(ann).access_envelope
        cipher = e.c.connections._cipher
        pid, iid = e.h.pid, e.integration_id

        assert await cipher.open(pid, iid, ann.key, "access", envelope) == next(t for t, v in e.server.access.items() if v["user"] == "ann")
        for args in (
            (pid, iid, bob.key, "access", envelope),  # moved to another subject
            (pid, str(PydanticObjectId()), ann.key, "access", envelope),  # moved to another integration
            (str(PydanticObjectId()), iid, ann.key, "access", envelope),  # moved to another project
            (pid, iid, ann.key, "refresh", envelope),  # used as the wrong kind of token
        ):
            with pytest.raises(CryptoError):
                await cipher.open(*args)


async def test_per_user_discovery_needs_the_callers_own_connection():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        with pytest.raises(BadRequestError):
            await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        await e.connect(ADMIN_SUBJECT, "admin")
        summary = await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        assert summary.total == 4
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.ACTIVE


async def test_shared_integrations_ignore_a_users_own_connection():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "service")
        key = await e.enable_and_bind()
        await e.open_to_end_users()
        ann = await e.end_user("cust_ann")
        assert (await e.invoke(key, ann)).ok
        assert e.server.tokens_used_by("service") and e.server.tokens_used_by("ann") == []  # the project's credential, not a user's


# ====================================================================== refresh & dead grants
async def test_expiring_tokens_are_refreshed_and_the_rotated_token_is_kept():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        key = await e.enable_and_bind()
        old_access = e.stored(PROJECT).access_envelope.ciphertext
        e.expire(PROJECT)

        assert (await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))).ok
        assert e.server.counters["refresh"] == 1
        assert e.stored(PROJECT).access_envelope.ciphertext != old_access
        e.expire(PROJECT)
        assert (await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))).ok  # the rotated refresh token still works
        assert e.server.counters["refresh"] == 2


async def test_concurrent_calls_trigger_exactly_one_refresh():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        e.expire(PROJECT)
        e.server.refresh_delay = 0.05  # a real suspension point, so concurrent callers genuinely interleave
        integration = await e.c.integrations.get(e.h.project.id, e.integration_id)
        from app.services.tools.connections import ConnectionTokenService

        service = ConnectionTokenService(
            e.h.connections_repo, e.h.oauth_clients, e.h.integrations, e.c.connections._cipher, e.c.connections._oauth, e.h.shared.locks
        )
        results = await asyncio.gather(*[service.credentials_for(integration, PROJECT) for _ in range(12)])
        assert e.server.counters["refresh"] == 1
        assert len({r.headers["Authorization"] for r in results}) == 1


async def test_a_dead_grant_marks_the_connection_and_integration_and_stops_retrying():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        key = await e.enable_and_bind()
        e.server.fail_refresh, e.server.fail_refresh_error = 400, "invalid_grant"
        e.expire(PROJECT)

        first = await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))
        assert first.status in (InvocationStatus.AUTH_REQUIRED, InvocationStatus.DENIED)
        assert e.stored(PROJECT).status == ConnectionStatus.NEEDS_AUTH
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.NEEDS_AUTH
        hits = e.server.counters["refresh"]
        for _ in range(3):
            await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))
        assert e.server.counters["refresh"] == hits  # no further refresh attempts against a dead grant

        e.server.fail_refresh = None
        assert (await e.connect(PROJECT, "svc")).success  # reconnecting repairs it
        assert e.stored(PROJECT).status == ConnectionStatus.ACTIVE


async def test_invalid_client_is_also_treated_as_a_dead_grant():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        e.server.fail_refresh, e.server.fail_refresh_error = 401, "invalid_client"
        e.expire(PROJECT)
        integration = await e.c.integrations.get(e.h.project.id, e.integration_id)
        from app.services.tools.connections import ConnectionTokenService

        with pytest.raises(AuthRequired):
            await ConnectionTokenService(
                e.h.connections_repo, e.h.oauth_clients, e.h.integrations, e.c.connections._cipher, e.c.connections._oauth, e.h.shared.locks
            ).credentials_for(integration, PROJECT)
        assert e.stored(PROJECT).status == ConnectionStatus.NEEDS_AUTH


async def test_a_transient_refresh_failure_does_not_kill_the_grant():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        key = await e.enable_and_bind()
        e.server.fail_refresh, e.server.fail_refresh_error = 503, "temporarily_unavailable"
        e.expire(PROJECT)
        failed = await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))
        assert failed.status == InvocationStatus.UPSTREAM_ERROR and failed.retryable
        assert e.stored(PROJECT).status == ConnectionStatus.ACTIVE  # still connected

        e.server.fail_refresh = None
        assert (await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))).ok


async def test_one_users_dead_grant_does_not_affect_other_users_or_the_integration():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        await e.connect(ADMIN_SUBJECT, "admin")
        await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        key = await e.enable_and_bind()
        await e.open_to_end_users()
        ann, bob = await e.end_user("cust_ann"), await e.end_user("cust_bob")
        await e.connect(ann, "ann")
        await e.connect(bob, "bob")

        e.expire(ann)
        e.server.fail_refresh, e.server.fail_refresh_error = 400, "invalid_grant"
        assert (await e.invoke(key, ann)).status == InvocationStatus.AUTH_REQUIRED
        e.server.fail_refresh = None
        assert e.stored(ann).status == ConnectionStatus.NEEDS_AUTH and e.stored(bob).status == ConnectionStatus.ACTIVE
        assert (await e.invoke(key, bob)).ok
        assert (await e.c.integrations.get(e.h.project.id, e.integration_id)).status == IntegrationStatus.ACTIVE  # not a project outage


# ====================================================================== lifecycle
async def test_blocking_suspends_and_unblocking_resumes_and_erasure_deletes_tokens():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        ann = await e.end_user("cust_ann")
        await e.connect(ann, "ann")
        assert e.stored(ann).status == ConnectionStatus.ACTIVE

        await e.c.end_users.block(e.h.project.id, "cust_ann", ADMIN)
        assert e.stored(ann).status == ConnectionStatus.SUSPENDED
        await e.c.end_users.unblock(e.h.project.id, "cust_ann", ADMIN)
        assert e.stored(ann).status == ConnectionStatus.ACTIVE

        await e.c.end_users.delete(e.h.project.id, "cust_ann", ADMIN)
        assert not e.h.connections_repo.items  # tokens erased synchronously
        assert e.server.counters["revocations"] == 1  # and revoked at the provider
        assert any(ev["payload"].get("connections_erased") == 1 for ev in e.h.audit.events if ev["action"] == "end_user.deleted")


async def test_admins_can_revoke_a_connection_without_ever_seeing_it():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        key = await e.enable_and_bind()
        connection_id = str(e.stored(PROJECT).id)

        with pytest.raises(NotFoundError):
            await e.c.connections.revoke(e.h.project.id, str(PydanticObjectId()), connection_id, ADMIN)  # wrong integration
        await e.c.connections.revoke(e.h.project.id, e.integration_id, connection_id, ADMIN, reason="offboarded")
        assert not e.h.connections_repo.items and e.server.counters["revocations"] == 1
        assert "connection.revoked" in e.h.audit.actions()
        assert (await e.invoke(key, Subject(SubjectType.MEMBER, id="m"))).status != InvocationStatus.OK
        with pytest.raises(NotFoundError):
            await e.c.connections.revoke(e.h.project.id, e.integration_id, connection_id, ADMIN)


async def test_users_can_disconnect_only_their_own_connection():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        ann, bob = await e.end_user("cust_ann"), await e.end_user("cust_bob")
        await e.connect(ann, "ann")
        await e.connect(bob, "bob")
        assert await e.c.connections.disconnect(e.h.project.id, e.integration_id, ann, "ann") is True
        assert await e.c.connections.disconnect(e.h.project.id, e.integration_id, ann, "ann") is False
        assert e.stored(bob).status == ConnectionStatus.ACTIVE
        listing = await e.c.connections.list_for_subject(e.h.project.id, bob)
        assert [i.slug for _, i in listing] == ["remote"]
        assert await e.c.connections.list_for_subject(e.h.project.id, ann) == []


async def test_project_purge_removes_connections_sessions_clients_and_policy():
    from app.services.tools.common import ProjectAuditAdapter
    from app.services.tools.purge import ToolCascadePurger

    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        await e.connect(await e.end_user("cust_ann"), "ann")
        purger = ToolCascadePurger(
            e.h.invocations, e.h.bindings, e.h.settings_repo, e.h.tools_repo, e.h.end_users, e.h.integrations,
            ProjectAuditAdapter(e.h.audit), e.h.connections_repo, e.h.sessions, e.h.oauth_clients, e.h.policies,
        )
        counts = await purger.purge_project(e.h.project.id, "owner")
        assert counts["connections"] == 1 and counts["connect_sessions"] == 1 and counts["oauth_clients"] == 1 and counts["policies"] == 1
        assert not (e.h.connections_repo.items or e.h.sessions.items or e.h.oauth_clients.items or e.h.policies.items)


# ====================================================================== static per-user keys
async def scripted_per_user(h: Harness, mode: CredentialMode = CredentialMode.PER_USER, name: str = "X-Key"):
    h.scripted.catalog = [tool("lookup", schema={"type": "object", "properties": {"q": {"type": "string"}}, "additionalProperties": False})]
    created = await h.container.integrations.create(
        h.project.id,
        IntegrationCreateRequest(
            type=IntegrationType.CUSTOM, slug="svc", name="Svc", config={"kind": "scripted"},
            auth_profile=AuthProfile(auth_type=AuthType.API_KEY, credential_mode=mode, name=name, prefix="Key "),
        ),
        ADMIN,
    )
    h.scripted.probe_handler = lambda creds: (
        ProbeResult(healthy=True, status="healthy") if creds.headers.get(name, "").startswith("Key good") else ProbeResult(healthy=False, status="auth_failed")
    )
    return str(created.id)


async def test_per_user_api_keys_are_verified_stored_encrypted_and_used_only_for_their_owner():
    h = make_harness()
    iid = await scripted_per_user(h)
    flow = h.container.connect_flow
    policy = await h.container.policy.get(h.project.id)
    await h.container.policy.update(h.project.id, policy.revision, ADMIN, end_user_connect_enabled=True)

    with pytest.raises(BadRequestError) as exc:
        await flow.connect_static(h.project.id, iid, ADMIN_SUBJECT, "wrong-key", ADMIN)
    assert exc.value.code == "CREDENTIALS_REJECTED" and not h.connections_repo.items

    admin_conn = await flow.connect_static(h.project.id, iid, ADMIN_SUBJECT, "good-admin", ADMIN)
    assert "good-admin" not in admin_conn.model_dump_json()  # stored sealed
    assert "good-admin" not in ConnectionResponse.from_model(admin_conn).model_dump_json()
    await h.container.discovery.discover(h.project.id, iid, ADMIN, subject=ADMIN_SUBJECT)
    await h.container.integrations.set_end_user_access(h.project.id, iid, EndUserAccess.OPEN, True, ADMIN)
    _, setting = await h.container.catalog.get_tool(h.project.id, "svc.lookup")
    await h.container.tool_settings.update(h.project.id, "svc.lookup", ToolSettingUpdateRequest(revision=setting.revision, is_enabled=True), ADMIN)
    await h.container.bindings.replace(
        h.project.id,
        BindingReplaceRequest(subject_type=BindingSubjectType.PROJECT_DEFAULT, audience=[Audience.END_USERS], bindings=[BindingRule(target_type=BindingTargetType.INTEGRATION, target_id=iid)]),
        ADMIN,
    )

    ann = await h.container.end_users.resolve_subject(h.project.id, "cust_ann", "m")
    bob = await h.container.end_users.resolve_subject(h.project.id, "cust_bob", "m")
    await flow.connect_static(h.project.id, iid, ann, "good-ann", "ann")

    def run(subject):
        from app.core.tools.types import Actor, ActorType, PrincipalContext

        return h.container.gateway.invoke(InvocationRequest(
            project_id=h.pid, tool_key="svc.lookup", arguments={"q": "x"},
            principal=PrincipalContext(project_id=h.pid, actor=Actor(ActorType.MACHINE, "m"), subject=subject),
        ))

    h.scripted.seen_credentials.clear()
    result = await run(ann)
    assert result.status == InvocationStatus.OK, (result.status, result.error_code)
    assert h.scripted.seen_credentials[-1].headers == {"X-Key": "Key good-ann"}  # Ann's own key, with the profile prefix
    h.scripted.calls.clear()
    assert (await run(bob)).status == InvocationStatus.AUTH_REQUIRED  # Bob never supplied a key; Ann's is not borrowed
    assert h.scripted.calls == []  # and nothing reached the upstream on Bob's behalf


async def test_static_keys_are_refused_where_they_do_not_apply():
    h = make_harness()
    iid = await scripted_per_user(h)
    flow = h.container.connect_flow
    for bad in ("", "x" * 5000, "has\nnewline", "nul\x00"):
        with pytest.raises(BadRequestError):
            await flow.connect_static(h.project.id, iid, ADMIN_SUBJECT, bad, ADMIN)
    with pytest.raises(ForbiddenError):  # end users still need the project's opt-in
        await flow.connect_static(h.project.id, iid, await h.container.end_users.resolve_subject(h.project.id, "cust", "m"), "good", "cust")
    with pytest.raises(BadRequestError):  # a project-wide subject cannot supply a per-user key
        await flow.connect_static(h.project.id, iid, PROJECT, "good", ADMIN)


# ====================================================================== strategy validation
@pytest.mark.parametrize(
    "oauth,secret",
    [
        ({"scopes": "read"}, False), ({"scopes": [1]}, False), ({"scopes": ["x"] * 51}, False),
        ({"client_id": ""}, False), ({"client_id": 5}, False), ({"surprise": 1}, False), ({}, True),
    ],
)
def test_oauth_profiles_are_validated(oauth, secret):
    from app.integrations.auth import OAuthAuthorizationCodeStrategy

    profile = AuthProfile(auth_type=AuthType.OAUTH_AUTHORIZATION_CODE, oauth=oauth, secret_id=PydanticObjectId() if secret else None)
    with pytest.raises(BadRequestError):
        OAuthAuthorizationCodeStrategy().validate(profile)


def test_valid_oauth_profiles_pass():
    from app.integrations.auth import OAuthAuthorizationCodeStrategy

    strategy = OAuthAuthorizationCodeStrategy()
    strategy.validate(AuthProfile(auth_type=AuthType.OAUTH_AUTHORIZATION_CODE))
    strategy.validate(AuthProfile(auth_type=AuthType.OAUTH_AUTHORIZATION_CODE, oauth={"scopes": ["a", "b"], "client_id": "c"}, secret_id=PydanticObjectId()))


async def test_the_atomic_claim_alone_stops_a_raced_callback():
    """
    Two callbacks can both read the session as ``started`` before either finishes. Only the atomic
    started -> completed transition decides the winner, so the loser must fail even with a stale read.
    """
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        _, params = await e.authorize(PROJECT, "svc")
        from tests.fakes.tool_repositories import _s  # noqa: F401

        state_hash = next(s.state_hash for s in e.h.sessions.items.values())
        stale = await e.h.sessions.get_by_state_hash(state_hash)  # snapshot while still `started`
        assert stale.status.value == "started"

        winner = await e.c.connect_flow.complete(params["state"], params["code"])
        assert winner.success

        async def stale_read(_hash):
            return stale.model_copy(deep=True)

        e.h.sessions.get_by_state_hash = stale_read  # type: ignore[assignment]
        loser = await e.c.connect_flow.complete(params["state"], params["code"])
        assert not loser.success and loser.error == "connect_session_expired"
        assert len(e.h.connections_repo.items) == 1


async def test_a_started_session_cannot_complete_after_it_expires():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        _, params = await e.authorize(PROJECT, "svc")
        next(iter(e.h.sessions.items.values())).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        outcome = await e.c.connect_flow.complete(params["state"], params["code"])
        assert not outcome.success and outcome.error == "connect_session_expired" and not e.h.connections_repo.items


async def test_changing_how_an_integration_authenticates_revokes_its_connections():
    async with env() as e:
        await e.create(CredentialMode.PROJECT_SHARED)
        await e.connect(PROJECT, "svc")
        assert len(e.h.connections_repo.items) == 1 and e.h.oauth_clients.items
        current = await e.c.integrations.get(e.h.project.id, e.integration_id)

        from app.schemas.tools import IntegrationUpdateRequest

        # Renaming changes nothing about credentials: the connection survives.
        renamed = await e.c.integrations.update(e.h.project.id, e.integration_id, IntegrationUpdateRequest(revision=current.revision, name="Renamed"), ADMIN)
        assert len(e.h.connections_repo.items) == 1

        await e.c.integrations.update(
            e.h.project.id, e.integration_id,
            IntegrationUpdateRequest(
                revision=renamed.revision,
                auth_profile=AuthProfile(auth_type=AuthType.OAUTH_AUTHORIZATION_CODE, credential_mode=CredentialMode.PER_USER, oauth={"scopes": ["read"]}),
            ),
            ADMIN,
        )
        assert not e.h.connections_repo.items and not e.h.oauth_clients.items  # the project connection is gone
        assert e.server.counters["revocations"] == 1  # and was revoked at the provider


async def test_deleting_an_integration_revokes_its_connections():
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        await e.connect(await e.end_user("cust_ann"), "ann")
        await e.c.integrations.delete(e.h.project.id, e.integration_id, ADMIN)
        assert not e.h.connections_repo.items and e.server.counters["revocations"] == 1


async def test_a_leftover_project_connection_is_never_used_for_a_per_user_integration():
    """Defence in depth: even if a project-level connection somehow exists, per-user means the user's own."""
    async with env() as e:
        await e.create(CredentialMode.PER_USER)
        await e.enable_policy()
        await e.connect(ADMIN_SUBJECT, "admin")
        await e.c.discovery.discover(e.h.project.id, e.integration_id, ADMIN, subject=ADMIN_SUBJECT)
        key = await e.enable_and_bind()
        await e.open_to_end_users()

        # Simulate stale/corrupt data: copy the admin's connection into a project-level record.
        from app.models.connection import ConnectionSubjectType

        stale = e.stored(ADMIN_SUBJECT).model_copy(deep=True)
        stale.id, stale.subject_type, stale.subject_id, stale.subject_key = PydanticObjectId(), ConnectionSubjectType.PROJECT, None, "project"
        e.h.connections_repo.items[str(stale.id)] = stale

        ann = await e.end_user("cust_ann")
        from app.core.tools.types import Actor, ActorType, PrincipalContext

        toolset = await e.c.toolset.resolve_toolset(PrincipalContext(project_id=e.h.pid, actor=Actor(ActorType.MACHINE, "m"), subject=ann))
        assert toolset.tools == [] and [a.integration for a in toolset.auth_required] == ["remote"]
        assert (await e.invoke(key, ann)).status == InvocationStatus.AUTH_REQUIRED
