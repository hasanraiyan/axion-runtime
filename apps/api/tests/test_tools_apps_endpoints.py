"""
HTTP tests for the MCP App endpoints (SRS-07 FR-45..FR-51): role and credential matrix, the approval flow,
rendering for members and end users, and the bridge. A scripted integration stands in for the MCP server here
(the real SDK server is exercised in ``test_tools_apps``); app resources are placed directly in the fake store.
"""
import hashlib

import pytest
from beanie import PydanticObjectId
from fastapi.testclient import TestClient

from app.api.deps import get_credential_repository, get_project_member_repository, get_project_repository
from app.main import app
from app.models.app_resource import AppResource
from app.services.tools.providers import get_tools_container
from tests.fakes.credential_repository import InMemoryProjectCredentialRepository
from tests.test_tools_endpoints import FakeMembers, base, bearer, make_key
from tests.tools_harness import make_harness, tool

pytestmark = pytest.mark.usefixtures("tool_models")

HTML = "<html><body>widget</body></html>"
HASH = hashlib.sha256(HTML.encode()).hexdigest()
URI = "ui://x/app"


@pytest.fixture
def api():
    h = make_harness()
    creds = InMemoryProjectCredentialRepository()
    app.dependency_overrides[get_tools_container] = lambda: h.container
    app.dependency_overrides[get_project_repository] = lambda: h.projects
    app.dependency_overrides[get_project_member_repository] = lambda: FakeMembers(h.project.id)
    app.dependency_overrides[get_credential_repository] = lambda: creds
    with TestClient(app) as client:
        yield client, h, creds
    app.dependency_overrides.clear()


def put_app(h, integration_id: str, content: str = HTML, uri: str = URI) -> str:
    doc = AppResource(
        project_id=h.project.id, integration_id=integration_id, uri=uri, mime_type="text/html;profile=mcp-app", content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest(), size_bytes=len(content),
        declared_csp={"connectDomains": ["https://api.example.com"]}, declared_permissions=["geolocation"],
    )
    doc.id = PydanticObjectId()
    h.app_repo.items[str(doc.id)] = doc
    return str(doc.id)


def onboard(client, h, slug="svc", with_apps=True):
    ui = {"resource_uri": URI, "visibility": ["app"]} if with_apps else None
    h.scripted.catalog = [
        tool("refresh", ui=ui, schema={"type": "object", "properties": {}}),
        tool("chat", schema={"type": "object", "properties": {"q": {"type": "string"}}, "additionalProperties": False}),
    ]
    r = client.post(base(h) + "/integrations", json={"type": "custom", "slug": slug, "name": slug.title(), "config": {"kind": "scripted"}}, headers=bearer("user_admin"))
    assert r.status_code == 201, r.text
    iid = r.json()["data"]["integration"]["id"]
    for name in ("refresh", "chat"):
        rev = client.get(base(h) + f"/tools/{slug}.{name}", headers=bearer("user_admin")).json()["data"]["setting"]["revision"]
        client.patch(base(h) + f"/tools/{slug}.{name}", json={"revision": rev, "is_enabled": True}, headers=bearer("user_admin"))
    return iid


def bind(client, h, iid, audience=("members", "end_users")):
    r = client.put(
        base(h) + "/tool-bindings",
        json={"subject_type": "project_default", "audience": list(audience), "bindings": [{"target_type": "integration", "target_id": iid}]},
        headers=bearer("user_admin"),
    )
    assert r.status_code == 200, r.text


def approve(client, h, rid, user="user_admin", csp=None, permissions=None, content_hash=HASH):
    return client.post(
        base(h) + f"/app-resources/{rid}/approve",
        json={"content_hash": content_hash, "csp": {"connectDomains": ["https://api.example.com"]} if csp is None else csp, "permissions": ["geolocation"] if permissions is None else permissions},
        headers=bearer(user),
    )


def end_user_headers(client, h, creds, external_id="cust_1", capabilities=None):
    key = make_key(h, creds, ["end_users:assert"])
    token = client.post(base(h) + f"/end-users/{external_id}/sessions", json={"capabilities": capabilities} if capabilities else {}, headers=key).json()["data"]["token"]
    return {"X-Axion-End-User-Token": token}


# ============================================================== admin endpoints
def test_listing_apps_never_includes_the_html(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    listing = client.get(base(h) + f"/integrations/{iid}/apps", headers=bearer("user_viewer"))
    assert listing.status_code == 200
    item = listing.json()["data"][0]
    assert item["id"] == rid and item["approved"] is False and item["content_hash"] == HASH
    assert "widget" not in listing.text and "html" not in item and "content" not in item


def test_only_admins_approve_and_only_declared_grants_are_accepted(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    assert approve(client, h, rid, user="user_member").status_code == 403
    assert approve(client, h, rid, user="user_viewer").status_code == 403
    key = make_key(h, creds, ["*"])
    assert client.post(base(h) + f"/app-resources/{rid}/approve", json={"content_hash": HASH}, headers=key).status_code == 403

    assert approve(client, h, rid, csp={"connectDomains": ["https://evil.example"]}).status_code == 400
    assert approve(client, h, rid, permissions=["camera"]).status_code == 400
    stale = approve(client, h, rid, content_hash="0" * 64)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "APP_CONTENT_CHANGED"
    assert client.post(base(h) + f"/app-resources/{rid}/approve", json={"content_hash": "short"}, headers=bearer("user_admin")).status_code == 422

    ok = approve(client, h, rid)
    assert ok.status_code == 200 and ok.json()["data"]["approved"] is True and ok.json()["data"]["approved_by"] == "user_admin"


def test_sync_is_admin_only_and_needs_an_mcp_integration(api):
    client, h, creds = api
    iid = onboard(client, h)
    assert client.post(base(h) + f"/integrations/{iid}/apps/sync", headers=bearer("user_member")).status_code == 403
    assert client.post(base(h) + f"/integrations/{iid}/apps/sync", headers=make_key(h, creds, ["*"])).status_code == 403
    # The scripted integration type does not provide MCP resources: a clear 400, not a crash.
    assert client.post(base(h) + f"/integrations/{iid}/apps/sync", headers=bearer("user_admin")).status_code == 400
    assert client.get(base(h) + f"/integrations/{iid}/resources", headers=bearer("user_admin")).status_code == 400
    assert client.get(base(h) + f"/integrations/{iid}/prompts", headers=bearer("user_admin")).status_code == 400


# ============================================================== rendering
def test_content_is_refused_until_approved_then_served_with_only_approved_grants(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    path = base(h) + f"/app-resources/{rid}/content"

    blocked = client.get(path, headers=bearer("user_member"))
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "APP_NOT_APPROVED"
    approve(client, h, rid, csp={}, permissions=[])  # approve the code, grant nothing else

    served = client.get(path, headers=bearer("user_member"))
    assert served.status_code == 200 and served.headers["cache-control"] == "no-store"
    data = served.json()["data"]
    assert data["html"] == HTML and data["content_hash"] == HASH and data["csp"] == {} and data["permissions"] == []


def test_content_roles_and_credentials(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    approve(client, h, rid)
    path = base(h) + f"/app-resources/{rid}/content"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=bearer("user_viewer")).status_code == 403  # viewers cannot use apps
    assert client.get(path, headers=bearer("user_outsider")).status_code == 404
    assert client.get(path, headers=make_key(h, creds, ["*"])).status_code == 401  # an API key is a backend, not a person: authenticate as one
    assert client.get(base(h) + "/app-resources/64b000000000000000000000/content", headers=bearer("user_member")).status_code == 404
    assert client.get(path, headers=bearer("user_member")).status_code == 200


def test_end_users_need_the_apps_capability_and_an_opened_integration(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    approve(client, h, rid)
    path = base(h) + f"/app-resources/{rid}/content"

    ann = end_user_headers(client, h, creds, "cust_ann")
    assert client.get(path, headers=ann).status_code == 404  # the integration is closed to end users: it "does not exist"
    client.put(base(h) + f"/integrations/{iid}/end-user-access", json={"access": "open", "acknowledge_shared_identity": True}, headers=bearer("user_admin"))
    assert client.get(path, headers=ann).status_code == 200

    no_cap = end_user_headers(client, h, creds, "cust_nocap", capabilities=["connections:own"])
    assert client.get(path, headers=no_cap).status_code == 403
    assert client.get(path, headers={"X-Axion-End-User-Token": "garbage"}).status_code == 401

    client.post(base(h) + "/end-users/cust_ann/block", headers=make_key(h, creds, ["end_users:manage"]))
    assert client.get(path, headers=ann).status_code == 403  # blocked users lose their widgets too


def test_a_changed_app_stops_rendering_everywhere(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    approve(client, h, rid)
    path = base(h) + f"/app-resources/{rid}/content"
    assert client.get(path, headers=bearer("user_member")).status_code == 200

    stored = h.app_repo.items[rid]
    stored.content, stored.content_hash = "<html>swapped</html>", hashlib.sha256(b"<html>swapped</html>").hexdigest()
    assert client.get(path, headers=bearer("user_member")).status_code == 409  # approval was for different code


# ============================================================== bridge: tool calls
def call(client, h, rid, tool_key, headers, args=None):
    return client.post(base(h) + "/apps/tool-calls", json={"resource_id": rid, "tool_key": tool_key, "arguments": args or {}}, headers=headers)


def test_an_approved_app_calls_only_tools_that_declare_it(api):
    client, h, creds = api
    iid = onboard(client, h)
    bind(client, h, iid)
    rid = put_app(h, iid)
    member = bearer("user_member")

    assert call(client, h, rid, "svc.refresh", member).status_code == 409  # not approved yet
    approve(client, h, rid)
    ok = call(client, h, rid, "svc.refresh", member)
    assert ok.status_code == 200 and ok.json()["data"]["status"] == "ok"
    denied = call(client, h, rid, "svc.chat", member, {"q": "x"}).json()["data"]
    assert denied["status"] == "denied" and denied["error_code"] == "tool_unavailable"  # no UI metadata: not an app endpoint
    assert h.invocations.items[-1].origin == "app_widget"


def test_apps_cannot_reach_other_integrations_or_unknown_tools(api):
    client, h, creds = api
    iid = onboard(client, h)
    bind(client, h, iid)
    rid = put_app(h, iid)
    approve(client, h, rid)
    other = onboard(client, h, slug="other")
    bind(client, h, other)
    r = call(client, h, rid, "other.refresh", bearer("user_member"))
    assert r.status_code == 403 and r.json()["error"]["code"] == "APP_ORIGIN_VIOLATION"
    ghost = call(client, h, rid, "svc.ghost", bearer("user_member")).json()["data"]
    assert ghost["status"] == "denied"


def test_bridge_roles_and_validation(api):
    client, h, creds = api
    iid = onboard(client, h)
    bind(client, h, iid)
    rid = put_app(h, iid)
    approve(client, h, rid)
    assert call(client, h, rid, "svc.refresh", {}).status_code == 401
    assert call(client, h, rid, "svc.refresh", bearer("user_viewer")).status_code == 403
    assert call(client, h, rid, "svc.refresh", make_key(h, creds, ["tools:invoke", "*"])).status_code == 401  # even a full-scope key
    assert client.post(base(h) + "/apps/tool-calls", json={"tool_key": "svc.refresh"}, headers=bearer("user_member")).status_code == 422


def test_end_users_calling_through_an_app_follow_the_audience_rules(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    approve(client, h, rid)
    client.put(base(h) + f"/integrations/{iid}/end-user-access", json={"access": "open", "acknowledge_shared_identity": True}, headers=bearer("user_admin"))
    ann = end_user_headers(client, h, creds, "cust_ann")

    bind(client, h, iid, audience=("members",))  # end users not in the audience
    assert call(client, h, rid, "svc.refresh", ann).json()["data"]["status"] == "denied"
    bind(client, h, iid, audience=("members", "end_users"))
    assert call(client, h, rid, "svc.refresh", ann).json()["data"]["status"] == "ok"
    record = h.invocations.items[-1]
    assert record.origin == "app_widget" and record.subject["type"] == "end_user"


def test_resource_reads_need_an_approved_app_and_a_person(api):
    client, h, creds = api
    iid = onboard(client, h)
    rid = put_app(h, iid)
    body = {"resource_id": rid, "uri": "notes://readme"}
    assert client.post(base(h) + "/apps/resource-reads", json=body).status_code == 401
    assert client.post(base(h) + "/apps/resource-reads", json=body, headers=bearer("user_member")).status_code == 409
    approve(client, h, rid)
    # The scripted integration type has no resources: a clear 400 rather than an error from deep inside.
    assert client.post(base(h) + "/apps/resource-reads", json=body, headers=bearer("user_member")).status_code == 400
    assert client.post(base(h) + "/apps/resource-reads", json={"resource_id": rid}, headers=bearer("user_member")).status_code == 422
