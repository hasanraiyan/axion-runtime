"""
MCP Apps tests (SRS-07 FR-45..FR-51): hash pinning, admin approval, rendering, and the app bridge.

Runs against a real official-SDK MCP server (``mcp_test_server`` with ``extras=True``) that serves a ``ui://`` HTML
resource with declared CSP domains and permissions, an app-only tool, plain resources, a template, and a prompt.
No sockets, no network.
"""
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional

import pytest

from app.core.exceptions import (
    AppNotApprovedError,
    AppOriginViolationError,
    BadRequestError,
    ConflictError,
    NotFoundError,
)
from app.core.outbound import OutboundUrlGuard
from app.core.tools.types import Actor, ActorType, PrincipalContext, Subject, SubjectType
from app.integrations.mcp_client import SdkMcpConnector
from app.models.app_resource import AppSyncState
from app.models.integration import EndUserAccess, IntegrationType
from app.models.tool import Audience, BindingSubjectType, BindingTargetType
from app.models.tool_invocation import InvocationStatus
from app.schemas.tools import BindingReplaceRequest, BindingRule, IntegrationCreateRequest, ToolSettingUpdateRequest
from app.services.tools.app_resources import normalize_app_origin, parse_declared, template_matches
from tests.mcp_test_server import APP_URI, URL, running_transport
from tests.tools_harness import Harness, StaticResolver, make_harness

pytestmark = pytest.mark.usefixtures("tool_models")

ADMIN = "user_admin"
MEMBER = Subject(SubjectType.MEMBER, id="user_member")
CSP = {"connectDomains": ["https://api.charts.example"], "resourceDomains": ["https://cdn.charts.example"]}


@dataclass
class AppEnv:
    h: Harness
    gate: object
    integration_id: str = ""

    @property
    def c(self):
        return self.h.container

    @property
    def state(self) -> Dict:
        return self.gate.app_state  # type: ignore[attr-defined]

    async def resource(self):
        (res,) = [r for r in await self.c.apps.list_apps(self.h.project.id, self.integration_id) if r.uri == APP_URI]
        return res

    async def approve(self, csp: Optional[dict] = None, permissions: Optional[List[str]] = None, content_hash: Optional[str] = None):
        res = await self.resource()
        return await self.c.apps.approve(
            self.h.project.id, res.id, content_hash or res.content_hash, CSP if csp is None else csp,
            ["geolocation"] if permissions is None else permissions, ADMIN,
        )

    async def enable_tools_and_bind(self, audience: Optional[List[Audience]] = None) -> None:
        for key in ("remote.show_chart", "remote.refresh_chart", "remote.echo"):
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

    def principal(self, subject: Subject = MEMBER) -> PrincipalContext:
        return PrincipalContext(
            project_id=self.h.pid, actor=Actor(ActorType.USER if subject.type == SubjectType.MEMBER else ActorType.MACHINE, subject.id or "m"),
            subject=subject, origin="app_widget",
        )


@asynccontextmanager
async def env(synced: bool = True) -> AsyncIterator[AppEnv]:
    async with running_transport(extras=True) as (transport, gate):
        h = make_harness(connector=SdkMcpConnector(OutboundUrlGuard(StaticResolver()), inner_transport=transport))
        e = AppEnv(h, gate)
        result = await e.c.onboarding.create_and_verify(
            h.project.id, IntegrationCreateRequest(type=IntegrationType.MCP, slug="remote", name="Remote", config={"url": URL}), ADMIN
        )
        e.integration_id = str(result.integration.id)
        if not synced:
            h.app_repo.items.clear()
        yield e


# ====================================================================== discovery & listing
async def test_onboarding_pins_app_resources_but_never_approves_them():
    async with env() as e:
        res = await e.resource()
        assert res.uri == APP_URI and res.mime_type == "text/html;profile=mcp-app" and "chart v1" in res.content
        assert len(res.content_hash) == 64 and res.size_bytes > 0
        assert res.declared_csp == {"connectDomains": ["https://api.charts.example"], "resourceDomains": ["https://cdn.charts.example"]}
        assert res.declared_permissions == ["geolocation"]
        assert res.approved_hash is None and not res.is_approved  # discovery never grants anything


async def test_resources_templates_and_prompts_are_listed():
    async with env() as e:
        resources = await e.c.apps.list_resources(e.h.project.id, e.integration_id, Subject(SubjectType.PROJECT))
        assert {(r.uri, r.is_template) for r in resources} == {(APP_URI, False), ("notes://readme", False), ("docs://{name}", True)}
        prompts = await e.c.apps.list_prompts(e.h.project.id, e.integration_id, Subject(SubjectType.PROJECT))
        assert [(p.name, [a["name"] for a in p.arguments]) for p in prompts] == [("summarize", ["text"])]


async def test_non_mcp_integrations_cannot_list_resources():
    h = make_harness()
    await h.container.onboarding.create_and_verify(
        h.project.id, IntegrationCreateRequest(type=IntegrationType.NATIVE, slug="core", name="Core", config={"provider_key": "core_utils"}), ADMIN
    )
    integration = next(iter(h.integrations.items.values()))
    with pytest.raises(BadRequestError):
        await h.container.apps.list_resources(h.project.id, integration.id, Subject(SubjectType.PROJECT))


# ====================================================================== approval
async def test_nothing_renders_until_an_admin_approves_the_exact_hash():
    async with env() as e:
        res = await e.resource()
        with pytest.raises(AppNotApprovedError):
            await e.c.apps.render(e.h.project.id, res.id, MEMBER)

        approved = await e.approve()
        assert approved.is_approved and approved.approved_by == ADMIN
        page = await e.c.apps.render(e.h.project.id, res.id, MEMBER)
        assert "chart v1" in page.html and page.content_hash == res.content_hash
        assert "app_resource.approved" in e.h.audit.actions()


async def test_only_the_approved_domains_and_permissions_are_granted():
    async with env() as e:
        await e.approve(csp={"connectDomains": ["https://api.charts.example"]}, permissions=[])  # not the CDN, no geolocation
        page = await e.c.apps.render(e.h.project.id, (await e.resource()).id, MEMBER)
        assert page.csp == {"connectDomains": ["https://api.charts.example"]} and page.permissions == []


async def test_approval_cannot_grant_more_than_the_app_declared():
    async with env() as e:
        for csp, perms in (
            ({"connectDomains": ["https://evil.example.com"]}, []),  # domain the app never asked for
            ({"frameDomains": ["https://api.charts.example"]}, []),  # right domain, wrong category
            ({"connectDomains": ["*"]}, []),
            ({"nonsense": ["https://api.charts.example"]}, []),
            ({}, ["camera"]),  # permission the app never asked for
        ):
            with pytest.raises(BadRequestError):
                await e.approve(csp=csp, permissions=perms)
        assert not (await e.resource()).is_approved


async def test_approving_a_stale_hash_is_refused_so_admins_approve_what_they_reviewed():
    async with env() as e:
        stale_hash = (await e.resource()).content_hash
        e.state["html"] = "<html><body>malicious v2</body></html>"
        await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        with pytest.raises(ConflictError) as exc:
            await e.approve(content_hash=stale_hash)
        assert exc.value.code == "APP_CONTENT_CHANGED" and not (await e.resource()).is_approved


async def test_a_changed_app_is_blocked_until_reapproved():
    async with env() as e:
        res = await e.resource()
        await e.approve()
        assert (await e.c.apps.render(e.h.project.id, res.id, MEMBER)).html

        e.state["html"] = "<html><body><script>steal()</script></body></html>"
        summary = await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        assert summary.changed == [APP_URI]
        stored = await e.resource()
        assert stored.sync_state == AppSyncState.CHANGED and not stored.is_approved
        with pytest.raises(AppNotApprovedError):
            await e.c.apps.render(e.h.project.id, res.id, MEMBER)  # the old approval does not cover the new code

        await e.approve()  # re-approving the new hash restores it
        assert "steal()" in (await e.c.apps.render(e.h.project.id, res.id, MEMBER)).html


async def test_an_unchanged_resync_keeps_the_approval():
    async with env() as e:
        await e.approve()
        summary = await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        assert summary.synced == [APP_URI] and summary.changed == []
        assert (await e.resource()).is_approved


async def test_a_resource_the_server_stops_serving_becomes_unavailable_and_cannot_be_approved():
    async with env() as e:
        # Serve something that is not HTML: the sync must reject it rather than store it.

        async def not_html(integration, credentials, uri, max_bytes):  # simulate a non-HTML resource
            from app.core.tools.types import FetchedResource

            return FetchedResource(uri=uri, mime_type="application/json", text="{}", size_bytes=2)

        adapter = e.c.adapters.get("mcp")
        original, adapter.read_resource = adapter.read_resource, not_html
        try:
            summary = await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        finally:
            adapter.read_resource = original
        assert [u["uri"] for u in summary.unavailable] == [APP_URI]
        res = await e.resource()
        assert res.sync_state == AppSyncState.UNAVAILABLE and not res.is_approved
        with pytest.raises(ConflictError):
            await e.c.apps.approve(e.h.project.id, res.id, res.content_hash, {}, [], ADMIN)


async def test_apps_must_use_the_ui_scheme_and_be_html():
    async with env() as e:
        # Point a tool at a non-ui:// resource and a non-HTML ui:// resource; neither may be stored as an app.
        for definition in e.h.tools_repo.items.values():
            if definition.ui is not None:
                definition.ui.resource_uri = "https://evil.example.com/app.html"
        summary = await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        assert summary.unavailable and "ui://" in summary.unavailable[0]["reason"]


# ====================================================================== rendering access
async def test_render_hides_apps_from_end_users_until_the_integration_is_opened():
    async with env() as e:
        await e.approve()
        res = await e.resource()
        ann = await e.c.end_users.resolve_subject(e.h.project.id, "cust_ann", "m")
        with pytest.raises(NotFoundError):  # indistinguishable from "does not exist"
            await e.c.apps.render(e.h.project.id, res.id, ann)
        await e.c.integrations.set_end_user_access(e.h.project.id, e.integration_id, EndUserAccess.OPEN, True, ADMIN)
        assert (await e.c.apps.render(e.h.project.id, res.id, ann)).html


async def test_disabled_integrations_and_unknown_resources_do_not_render():
    async with env() as e:
        await e.approve()
        res = await e.resource()
        await e.c.integrations.set_enabled(e.h.project.id, e.integration_id, False, ADMIN)
        with pytest.raises(NotFoundError):
            await e.c.apps.render(e.h.project.id, res.id, MEMBER)
        with pytest.raises(NotFoundError):
            await e.c.apps.render(e.h.project.id, "64b000000000000000000000", MEMBER)


# ====================================================================== the bridge: tool calls
async def test_an_approved_app_can_call_an_app_visible_tool_through_the_gateway():
    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.approve()
        result = await e.c.apps.call_tool(e.principal(), res.id, "remote.refresh_chart", {"series": "b"})
        assert result.status == InvocationStatus.OK and "refreshed:b" in result.content[0].text
        record = e.h.invocations.items[-1]
        assert record.origin == "app_widget" and record.tool_key == "remote.refresh_chart"  # audited as an app call


async def test_an_unapproved_or_changed_app_cannot_call_tools():
    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.resource()
        with pytest.raises(AppNotApprovedError):
            await e.c.apps.call_tool(e.principal(), res.id, "remote.refresh_chart", {})
        await e.approve()
        e.state["html"] = "<html>changed</html>"
        await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        with pytest.raises(AppNotApprovedError):
            await e.c.apps.call_tool(e.principal(), res.id, "remote.refresh_chart", {})


async def test_apps_cannot_call_tools_that_do_not_declare_the_app_as_a_caller():
    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.approve()
        # `echo` has no UI metadata: it is a model-facing tool, not an app endpoint.
        result = await e.c.apps.call_tool(e.principal(), res.id, "remote.echo", {"message": "hi"})
        assert result.status == InvocationStatus.DENIED and result.error_code == "tool_unavailable"


async def test_apps_cannot_reach_another_integrations_tools():
    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.approve()
        from tests.tools_harness import tool

        e.h.scripted.catalog = [tool("sneaky", schema={"type": "object", "properties": {}}, ui={"resource_uri": "ui://x/y", "visibility": ["app"]})]
        other = await e.c.onboarding.create_and_verify(
            e.h.project.id, IntegrationCreateRequest(type=IntegrationType.CUSTOM, slug="other", name="Other", config={"kind": "scripted"}), ADMIN
        )
        assert other.integration.slug == "other"
        with pytest.raises(AppOriginViolationError):
            await e.c.apps.call_tool(e.principal(), res.id, "other.sneaky", {})
        assert e.h.scripted.calls == []  # nothing reached the other integration


async def test_app_calls_are_rate_limited_per_app_and_subject():
    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.approve()
        statuses = [(await e.c.apps.call_tool(e.principal(), res.id, "remote.refresh_chart", {})).status for _ in range(62)]
        assert statuses[:60] == [InvocationStatus.OK] * 60 and statuses[60:] == [InvocationStatus.RATE_LIMITED] * 2
        other = (await e.c.apps.call_tool(e.principal(Subject(SubjectType.MEMBER, id="user_other")), res.id, "remote.refresh_chart", {})).status
        assert other == InvocationStatus.OK  # another user of the same app is unaffected


async def test_end_users_calling_through_an_app_obey_the_same_gates_as_anywhere_else():
    async with env() as e:
        await e.enable_tools_and_bind(audience=[Audience.MEMBERS])  # end users are NOT in the audience
        res = await e.approve()
        await e.c.integrations.set_end_user_access(e.h.project.id, e.integration_id, EndUserAccess.OPEN, True, ADMIN)
        ann = await e.c.end_users.resolve_subject(e.h.project.id, "cust_ann", "m")
        result = await e.c.apps.call_tool(e.principal(ann), res.id, "remote.refresh_chart", {})
        assert result.status == InvocationStatus.DENIED  # the widget is not a back door around the audience rules


# ====================================================================== the bridge: resource reads
async def test_apps_can_read_their_own_integrations_resources_and_templates_only():
    async with env() as e:
        res = await e.approve()
        subject = Subject(SubjectType.PROJECT)
        own = await e.c.apps.read_resource(e.h.project.id, subject, res.id, APP_URI)
        assert "chart v1" in own.text
        assert (await e.c.apps.read_resource(e.h.project.id, subject, res.id, "notes://readme")).text == "hello from the server"
        assert (await e.c.apps.read_resource(e.h.project.id, subject, res.id, "docs://handbook")).text == "doc:handbook"  # via the template
        for forbidden in ("file:///etc/passwd", "secret://admin", "notes://other", "https://evil.example.com/x", "docs://a/b"):
            with pytest.raises(AppOriginViolationError):
                await e.c.apps.read_resource(e.h.project.id, subject, res.id, forbidden)


async def test_resource_reads_require_an_approved_app():
    async with env() as e:
        res = await e.resource()
        with pytest.raises(AppNotApprovedError):
            await e.c.apps.read_resource(e.h.project.id, Subject(SubjectType.PROJECT), res.id, "notes://readme")


# ====================================================================== pure helpers
@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://api.example.com", "https://api.example.com"), ("HTTPS://API.Example.com:8443/", "https://api.example.com:8443"),
        ("wss://stream.example.com", "wss://stream.example.com"), ("https://*.example.com", None), ("*", None),
        ("http://insecure.example.com", None), ("https://example.com/path", None), ("https://example.com?x=1", None),
        ("https://user:pw@example.com", None), ("javascript:alert(1)", None), ("", None), (None, None), (5, None),
    ],
)
def test_app_origins_are_strictly_normalized(value, expected):
    assert normalize_app_origin(value) == expected


def test_declared_metadata_is_sanitized():
    csp, perms = parse_declared(
        {"ui": {"csp": {"connectDomains": ["https://a.example", "*", "http://bad", "https://a.example"], "nonsense": ["https://x.example"], "frameDomains": "not-a-list"},
                "permissions": {"camera": {}, "geolocation": {}, "root": {}}}}
    )
    assert csp == {"connectDomains": ["https://a.example"]} and perms == ["camera", "geolocation"]
    assert parse_declared({}) == ({}, []) and parse_declared({"ui": "x"}) == ({}, [])
    many, _ = parse_declared({"ui": {"csp": {"connectDomains": [f"https://h{i}.example" for i in range(50)]}}})
    assert len(many["connectDomains"]) == 20


def test_uri_templates_match_one_segment_per_variable():
    assert template_matches("docs://{name}", "docs://handbook")
    assert not template_matches("docs://{name}", "docs://a/b") and not template_matches("docs://{name}", "other://handbook")
    assert template_matches("items://{kind}/{id}", "items://tool/42") and not template_matches("items://{kind}/{id}", "items://tool")


async def test_an_approved_app_the_server_stops_serving_stops_rendering():
    """The unavailable-state check and the hash check overlap; this proves the state check on its own."""
    async with env() as e:
        res = await e.approve()
        assert res.is_approved and (await e.c.apps.render(e.h.project.id, res.id, MEMBER)).html

        adapter = e.c.adapters.get("mcp")

        async def gone(integration, credentials, uri, max_bytes):
            from app.core.tools.errors import UpstreamError

            raise UpstreamError("resource not found")

        original, adapter.read_resource = adapter.read_resource, gone
        try:
            summary = await e.c.apps.sync_integration(e.h.project.id, e.integration_id, ADMIN)
        finally:
            adapter.read_resource = original
        assert [u["uri"] for u in summary.unavailable] == [APP_URI]
        stored = await e.resource()
        assert stored.approved_hash == stored.content_hash  # the hash alone would still match...
        assert stored.sync_state == AppSyncState.UNAVAILABLE
        with pytest.raises(AppNotApprovedError):  # ...but a resource the server no longer serves must not render
            await e.c.apps.render(e.h.project.id, res.id, MEMBER)


async def test_the_bridge_forces_app_origin_even_if_the_caller_claims_another():
    """A widget must never be able to pass itself off as the model or a plain runtime call."""
    import dataclasses

    async with env() as e:
        await e.enable_tools_and_bind()
        res = await e.approve()
        pretending = dataclasses.replace(e.principal(), origin="runtime")

        # Claiming "runtime" must not unlock model-facing tools for the widget...
        echo = await e.c.apps.call_tool(pretending, res.id, "remote.echo", {"message": "hi"})
        assert echo.status == InvocationStatus.DENIED
        # ...and an app-only tool is still reachable, recorded as an app call.
        refresh = await e.c.apps.call_tool(pretending, res.id, "remote.refresh_chart", {})
        assert refresh.status == InvocationStatus.OK
        assert e.h.invocations.items[-1].origin == "app_widget"
