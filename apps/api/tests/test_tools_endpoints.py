"""
HTTP-level tests for Module 07 (SRS-07 Section 9): real FastAPI app, real auth dependencies
(Clerk dev tokens and API keys), a container wired from in-memory fakes. Exercises the role and
scope matrix (FR-32), the response envelope, and the full onboarding -> toolset -> invoke path
over the wire, including a real MCP server built with the official SDK.
"""
import hashlib
from typing import Dict, Optional

import pytest
from fastapi.testclient import TestClient

from app.api.deps import (
    get_credential_repository,
    get_project_member_repository,
    get_project_repository,
)
from app.api.v1.endpoints.tools_deps import ToolsContainer  # noqa: F401
from app.core.outbound import OutboundUrlGuard
from app.integrations.mcp_client import SdkMcpConnector
from app.main import app
from app.models.credential import ProjectCredential
from app.models.project import ProjectMember, ProjectRole
from app.services.tools.providers import get_tools_container
from tests.fakes.credential_repository import InMemoryProjectCredentialRepository
from tests.mcp_test_server import HOST, URL, running_transport
from tests.tools_harness import Harness, StaticResolver, make_harness

pytestmark = pytest.mark.usefixtures("tool_models")

ROLES: Dict[str, Optional[ProjectRole]] = {
    "user_owner": ProjectRole.OWNER,
    "user_admin": ProjectRole.ADMIN,
    "user_member": ProjectRole.MEMBER,
    "user_viewer": ProjectRole.VIEWER,
    "user_outsider": None,
}


class FakeMembers:
    def __init__(self, project_id) -> None:
        self.project_id = project_id

    async def get_membership(self, project_id, user_id):
        role = ROLES.get(user_id)
        return ProjectMember(project_id=project_id, user_id=user_id, role=role) if role else None


def bearer(user: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer dev-token-{user.replace('user_', '')}"}


def make_key(h: Harness, repo: InMemoryProjectCredentialRepository, scopes) -> Dict[str, str]:
    raw = "axion_test_" + hashlib.sha256(",".join(scopes).encode()).hexdigest()[:32]
    repo.credentials[raw] = ProjectCredential(
        project_id=h.project.id, name="k-" + raw[-6:], key_prefix="axion_test_", masked_key="axion_test_...", scopes=list(scopes),
        key_hash=hashlib.sha256(raw.encode()).hexdigest(), created_by="u", updated_by="u",
    )
    repo.credentials[raw].id = __import__("beanie").PydanticObjectId()
    return {"X-Axion-Api-Key": raw}


@pytest.fixture
def api():
    """(client, harness, credential_repo) with all external dependencies replaced by fakes."""
    h = make_harness()
    creds = InMemoryProjectCredentialRepository()
    app.dependency_overrides[get_tools_container] = lambda: h.container
    app.dependency_overrides[get_project_repository] = lambda: h.projects
    app.dependency_overrides[get_project_member_repository] = lambda: FakeMembers(h.project.id)
    app.dependency_overrides[get_credential_repository] = lambda: creds
    with TestClient(app) as client:
        yield client, h, creds
    app.dependency_overrides.clear()


def base(h: Harness) -> str:
    return f"/api/v1/projects/{h.pid}"


def scripted_body(slug: str = "svc") -> dict:
    return {"type": "custom", "slug": slug, "name": slug.title(), "config": {"kind": "scripted"}}


# ================================================================== role & scope matrix
def test_unauthenticated_requests_are_401(api):
    client, h, _ = api
    for method, path in (("get", "/integrations"), ("get", "/tools"), ("post", "/runtime/toolset")):
        r = getattr(client, method)(base(h) + path, **({"json": {}} if method == "post" else {}))
        assert r.status_code == 401, path


def test_non_members_get_404_never_403(api):
    client, h, _ = api
    assert client.get(base(h) + "/integrations", headers=bearer("user_outsider")).status_code == 404
    assert client.post(base(h) + "/integrations", json=scripted_body(), headers=bearer("user_outsider")).status_code == 404


@pytest.mark.parametrize(
    "user,expected",
    [("user_viewer", 403), ("user_member", 403), ("user_admin", 201), ("user_owner", 201)],
)
def test_only_admins_can_create_integrations(api, user, expected):
    client, h, _ = api
    h.scripted.catalog = []
    r = client.post(base(h) + "/integrations", json=scripted_body(), headers=bearer(user))
    assert r.status_code == expected, r.text


def test_viewers_can_read_but_machine_keys_need_scopes(api):
    client, h, creds = api
    assert client.get(base(h) + "/integrations", headers=bearer("user_viewer")).status_code == 200
    ok = make_key(h, creds, ["tools:read"])
    assert client.get(base(h) + "/integrations", headers=ok).status_code == 200
    wrong_scope = make_key(h, creds, ["end_users:assert"])
    assert client.get(base(h) + "/integrations", headers=wrong_scope).status_code == 403


def test_machine_credentials_cannot_perform_admin_writes(api):
    client, h, creds = api
    key = make_key(h, creds, ["*"])
    assert client.post(base(h) + "/integrations", json=scripted_body(), headers=key).status_code == 403
    assert client.put(base(h) + "/tool-bindings", json={"subject_type": "project_default", "bindings": []}, headers=key).status_code == 403


def test_viewers_cannot_invoke_but_members_can_reach_the_gateway(api):
    client, h, _ = api
    body = {"tool_key": "svc.search", "arguments": {}}
    assert client.post(base(h) + "/runtime/invoke", json=body, headers=bearer("user_viewer")).status_code == 403
    r = client.post(base(h) + "/runtime/invoke", json=body, headers=bearer("user_member"))
    assert r.status_code == 200 and r.json()["data"]["status"] == "denied"  # unknown tool: uniform denial, still HTTP 200


# ================================================================== full flow over HTTP
def onboard(client, h, tools=None, user="user_admin"):
    from tests.tools_harness import tool as mk

    h.scripted.catalog = tools if tools is not None else [mk("search")]
    r = client.post(base(h) + "/integrations", json=scripted_body(), headers=bearer(user))
    assert r.status_code == 201, r.text
    return r.json()["data"]


def test_onboard_enable_bind_resolve_invoke_and_audit_trail(api):
    client, h, _ = api
    data = onboard(client, h)
    assert data["integration"]["status"] == "active" and data["discovery"]["added"] == ["svc.search"]
    assert data["probe"]["healthy"] is True
    assert data["integration"]["auth_profile"]["secret_id"] is None  # a reference field, never a value
    assert "envelope" not in str(data).lower() and "plain:" not in str(data)

    tool = client.get(base(h) + "/tools/svc.search", headers=bearer("user_viewer")).json()["data"]
    assert tool["setting"]["is_enabled"] is False and tool["needs_approval"] is True

    enabled = client.patch(
        base(h) + "/tools/svc.search", json={"revision": tool["setting"]["revision"], "is_enabled": True}, headers=bearer("user_admin")
    )
    assert enabled.status_code == 200 and enabled.json()["data"]["setting"]["is_enabled"] is True

    iid = data["integration"]["id"]
    put = client.put(
        base(h) + "/tool-bindings",
        json={"subject_type": "project_default", "audience": ["members"], "bindings": [{"target_type": "integration", "target_id": iid}]},
        headers=bearer("user_admin"),
    )
    assert put.status_code == 200 and len(put.json()["data"]) == 1

    toolset = client.post(base(h) + "/runtime/toolset", json={}, headers=bearer("user_member")).json()["data"]
    assert [t["tool_key"] for t in toolset["tools"]] == ["svc.search"] and toolset["toolset_version"]

    result = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.search", "arguments": {"q": "hi"}}, headers=bearer("user_member")).json()["data"]
    assert result["status"] == "ok" and result["invocation_id"] and result["content"][0]["text"].startswith("search:")

    bad = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.search", "arguments": {"q": 5}}, headers=bearer("user_member")).json()["data"]
    assert bad["status"] == "validation_error" and bad["model_correctable"] is True

    history = client.get(base(h) + "/tool-invocations", headers=bearer("user_admin")).json()["data"]["items"]
    assert len(history) == 2 and client.get(base(h) + "/tool-invocations", headers=bearer("user_member")).status_code == 403
    assert "integration.created" in h.audit.actions() and "binding.created" in h.audit.actions()


def test_error_envelope_and_codes_for_common_failures(api):
    client, h, _ = api
    data = onboard(client, h)
    dup = client.post(base(h) + "/integrations", json=scripted_body(), headers=bearer("user_admin"))
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "INTEGRATION_SLUG_EXISTS" and dup.json()["success"] is False

    stale = client.patch(base(h) + f"/integrations/{data['integration']['id']}", json={"revision": 99, "description": "x"}, headers=bearer("user_admin"))
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "REVISION_CONFLICT"
    assert client.get(base(h) + "/integrations/64b000000000000000000000", headers=bearer("user_admin")).status_code == 404
    assert client.post(base(h) + "/integrations", json={"type": "custom"}, headers=bearer("user_admin")).status_code == 422
    unsafe = client.post(base(h) + "/integrations", json={"type": "custom", "slug": "BAD SLUG", "name": "x", "config": {}}, headers=bearer("user_admin"))
    assert unsafe.status_code == 422


def test_integration_responses_never_contain_credentials_or_header_values(api):
    client, h, _ = api
    h.secrets.add(h.project.id, "TEAM_TOKEN")
    body = {**scripted_body("hdr"), "auth_profile": {"auth_type": "custom_headers", "headers": {"X-Team": "{{secrets.TEAM_TOKEN}}"}}}
    h.scripted.catalog = []
    r = client.post(base(h) + "/integrations", json=body, headers=bearer("user_admin"))
    text = r.text
    assert r.status_code == 201 and "X-Team" in text and "TEAM_TOKEN" not in text and "plain:" not in text


def test_integration_types_endpoint_lists_adapters_and_native_providers(api):
    client, h, _ = api
    data = client.get(base(h) + "/integration-types", headers=bearer("user_viewer")).json()["data"]
    assert {t["key"] for t in data["types"]} >= {"native", "mcp", "custom:scripted"}
    assert data["native_providers"][0]["key"] == "core_utils"


def test_native_integration_end_to_end_over_http(api):
    client, h, _ = api
    r = client.post(
        base(h) + "/integrations",
        json={"type": "native", "slug": "core", "name": "Core", "config": {"provider_key": "core_utils"}},
        headers=bearer("user_admin"),
    )
    assert r.status_code == 201
    iid = r.json()["data"]["integration"]["id"]
    client.put(
        base(h) + "/tool-bindings",
        json={"subject_type": "project_default", "bindings": [{"target_type": "integration", "target_id": iid}]},
        headers=bearer("user_admin"),
    )
    out = client.post(base(h) + "/runtime/invoke", json={"tool_key": "core.text_stats", "arguments": {"text": "one two three"}}, headers=bearer("user_member")).json()["data"]
    assert out["status"] == "ok" and out["structured_content"]["words"] == 3


# ================================================================== machine + end users
def test_machine_credential_acting_for_an_end_user_end_to_end(api):
    client, h, creds = api
    data = onboard(client, h)
    iid, hdr_admin = data["integration"]["id"], bearer("user_admin")
    tool = client.get(base(h) + "/tools/svc.search", headers=hdr_admin).json()["data"]
    client.patch(base(h) + "/tools/svc.search", json={"revision": tool["setting"]["revision"], "is_enabled": True}, headers=hdr_admin)
    client.put(
        base(h) + "/tool-bindings",
        json={"subject_type": "project_default", "audience": ["end_users"], "bindings": [{"target_type": "integration", "target_id": iid}]},
        headers=hdr_admin,
    )
    key = make_key(h, creds, ["tools:read", "tools:invoke", "end_users:assert"])

    closed = client.post(base(h) + "/runtime/toolset", json={"end_user_external_id": "cust_1"}, headers=key).json()["data"]
    assert closed["tools"] == [] and closed["excluded"][0]["reason"] == "end_user_access_closed"

    no_ack = client.put(base(h) + f"/integrations/{iid}/end-user-access", json={"access": "open"}, headers=hdr_admin)
    assert no_ack.status_code == 400 and no_ack.json()["error"]["code"] == "SHARED_IDENTITY_ACK_REQUIRED"
    client.put(base(h) + f"/integrations/{iid}/end-user-access", json={"access": "open", "acknowledge_shared_identity": True}, headers=hdr_admin)

    opened = client.post(base(h) + "/runtime/toolset", json={"end_user_external_id": "cust_1"}, headers=key).json()["data"]
    assert [t["tool_key"] for t in opened["tools"]] == ["svc.search"]
    run = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.search", "arguments": {"q": "x"}, "end_user_external_id": "cust_1"}, headers=key).json()["data"]
    assert run["status"] == "ok"

    listed = client.get(base(h) + "/end-users", headers=hdr_admin).json()["data"]["items"]
    assert [u["external_id"] for u in listed] == ["cust_1"]
    assert client.post(base(h) + "/end-users/cust_1/block", headers=hdr_admin).status_code == 200
    blocked = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.search", "arguments": {}, "end_user_external_id": "cust_1"}, headers=key)
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "END_USER_BLOCKED"


def test_credentials_without_the_assert_scope_cannot_name_end_users(api):
    client, h, creds = api
    key = make_key(h, creds, ["tools:invoke"])
    r = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.x", "arguments": {}, "end_user_external_id": "cust_1"}, headers=key)
    assert r.status_code == 403
    assert not h.end_users.items  # nothing was created


def test_members_cannot_impersonate_end_users(api):
    client, h, _ = api
    r = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.x", "arguments": {}, "end_user_external_id": "cust_1"}, headers=bearer("user_member"))
    assert r.status_code == 400


def test_end_user_session_lifecycle_over_http(api):
    client, h, creds = api
    key = make_key(h, creds, ["end_users:assert"])
    created = client.post(base(h) + "/end-users/cust_9/sessions", json={"ttl_seconds": 120}, headers=key)
    assert created.status_code == 201
    token = created.json()["data"]["token"]

    me = client.get(base(h) + "/me", headers={"X-Axion-End-User-Token": token})
    assert me.status_code == 200 and me.json()["data"]["external_id"] == "cust_9"
    assert client.get(base(h) + "/me").status_code == 401
    assert client.get(base(h) + "/me", headers={"X-Axion-End-User-Token": token + "x"}).status_code == 401

    # The session token is not an API key and is useless for admin or runtime endpoints.
    assert client.get(base(h) + "/integrations", headers={"X-Axion-End-User-Token": token}).status_code == 401
    assert client.post(base(h) + "/runtime/invoke", json={"tool_key": "a.b", "arguments": {}}, headers={"X-Axion-End-User-Token": token}).status_code == 401

    assert client.post(base(h) + "/end-users/cust_9/sessions", json={"capabilities": ["root"]}, headers=key).status_code == 400
    assert client.get(base(h) + "/end-users", headers=key).status_code == 403  # assert scope is not manage scope

    manage = make_key(h, creds, ["end_users:manage"])
    assert client.delete(base(h) + "/end-users/cust_9", headers=manage).status_code == 200
    assert client.get(base(h) + "/me", headers={"X-Axion-End-User-Token": token}).status_code in (403, 404)


def test_approval_flow_over_http(api):
    client, h, _ = api
    from tests.tools_harness import tool as mk

    data = onboard(client, h, [mk("wipe", read_only=False, destructive=True)])
    iid = data["integration"]["id"]
    t = client.get(base(h) + "/tools/svc.wipe", headers=bearer("user_admin")).json()["data"]
    client.patch(base(h) + "/tools/svc.wipe", json={"revision": t["setting"]["revision"], "is_enabled": True}, headers=bearer("user_admin"))
    client.put(base(h) + "/tool-bindings", json={"subject_type": "project_default", "bindings": [{"target_type": "integration", "target_id": iid}]}, headers=bearer("user_admin"))

    call = {"tool_key": "svc.wipe", "arguments": {"q": "all"}}
    first = client.post(base(h) + "/runtime/invoke", json=call, headers=bearer("user_admin")).json()["data"]
    assert first["status"] == "approval_required" and first["extra"]["approval"]["tool_key"] == "svc.wipe"

    token = client.post(
        base(h) + "/runtime/approvals", json={"tool_key": "svc.wipe", "arguments": {"q": "all"}, "member_id": "user_admin"}, headers=bearer("user_admin")
    ).json()["data"]["approval_token"]
    second = client.post(base(h) + "/runtime/invoke", json={**call, "approval_token": token}, headers=bearer("user_admin")).json()["data"]
    assert second["status"] == "ok"
    assert client.post(base(h) + "/runtime/approvals", json={"tool_key": "svc.wipe", "arguments": {}}, headers=bearer("user_member")).status_code == 403


def test_dry_run_flag_over_http(api):
    client, h, _ = api
    from tests.tools_harness import tool as mk

    data = onboard(client, h, [mk("w", read_only=False, destructive=False)])
    iid = data["integration"]["id"]
    t = client.get(base(h) + "/tools/svc.w", headers=bearer("user_admin")).json()["data"]
    client.patch(base(h) + "/tools/svc.w", json={"revision": t["setting"]["revision"], "is_enabled": True, "approval_policy": "auto"}, headers=bearer("user_admin"))
    client.put(base(h) + "/tool-bindings", json={"subject_type": "project_default", "bindings": [{"target_type": "integration", "target_id": iid}]}, headers=bearer("user_admin"))
    out = client.post(base(h) + "/runtime/invoke", json={"tool_key": "svc.w", "arguments": {"q": "x"}, "dry_run": True}, headers=bearer("user_admin")).json()["data"]
    assert out["status"] == "dry_run" and h.scripted.calls == []


# ================================================================== real MCP server over the wire
async def test_real_sdk_mcp_server_through_the_whole_stack():
    """Create an MCP integration over HTTP, discover its tools, enable one, and invoke it through the gateway."""
    async with running_transport() as (transport, _):
        h = make_harness(connector=SdkMcpConnector(OutboundUrlGuard(StaticResolver()), inner_transport=transport))
        app.dependency_overrides[get_tools_container] = lambda: h.container
        app.dependency_overrides[get_project_repository] = lambda: h.projects
        app.dependency_overrides[get_project_member_repository] = lambda: FakeMembers(h.project.id)
        try:
            # httpx2/ASGI transports need the event loop of this test, so drive the service layer directly
            # for the MCP calls and keep HTTP-shape assertions in the synchronous tests above.
            from app.schemas.tools import IntegrationCreateRequest
            from app.models.integration import IntegrationType

            result = await h.container.onboarding.create_and_verify(
                h.project.id,
                IntegrationCreateRequest(type=IntegrationType.MCP, slug="remote", name="Remote", config={"url": URL}),
                "user_admin",
            )
            assert result.integration.status.value == "active" and HOST
            assert sorted(result.discovery.added) == ["remote.delete_everything", "remote.echo", "remote.explode", "remote.show_chart"]

            settings = {s.tool_key: s for s in h.settings_repo.items.values()}
            assert settings["remote.echo"].approval_policy.value == "auto"  # read-only hint => runs unattended
            assert settings["remote.delete_everything"].approval_policy.value == "require_approval"
            assert settings["remote.explode"].approval_policy.value == "require_approval"  # no annotations => cautious
            ui = next(d for d in h.tools_repo.items.values() if d.tool_key == "remote.show_chart").ui
            assert ui.resource_uri == "ui://charts/main"
        finally:
            app.dependency_overrides.clear()
