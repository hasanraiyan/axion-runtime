"""
HTTP tests for the connection endpoints (SRS-07 Sections 9.2 and 9.6): the public OAuth browser endpoints,
admin and machine management, self-service for members and end users, and tool policy. Uses a fake OAuth
provider (the real protocol path is covered by ``test_tools_connections``) so the app runs in the TestClient's
own event loop without sockets.
"""
from typing import Optional
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_credential_repository, get_project_member_repository, get_project_repository
from app.core.tools.oauth import DiscoveredOAuth, RegisteredClient, TokenSet
from app.main import app
from app.services.tools.providers import get_tools_container
from tests.fakes.credential_repository import InMemoryProjectCredentialRepository
from tests.test_tools_endpoints import FakeMembers, base, bearer, make_key
from tests.tools_harness import Harness, make_harness

pytestmark = pytest.mark.usefixtures("tool_models")

RETURN = "https://app.example.com/connected"
ORIGIN = "https://app.example.com"
SERVER_URL = "https://mcp.example.com/mcp"


class FakeOAuthFlow:
    """Deterministic stand-in for the OAuth provider; records calls."""

    def __init__(self) -> None:
        self.revoked: list = []
        self.fail_exchange = False

    async def discover(self, resource_url, allowed_hosts=None):
        return DiscoveredOAuth(
            issuer="https://as.example.com", resource=resource_url, authorization_endpoint="https://as.example.com/authorize",
            token_endpoint="https://as.example.com/token", registration_endpoint="https://as.example.com/register",
            revocation_endpoint="https://as.example.com/revoke",
        )

    async def register_client(self, discovered, redirect_uri, client_name):
        return RegisteredClient(client_id="fake-client")

    def authorization_url(self, endpoint, client_id, redirect_uri, state, code_verifier, scopes, resource):
        return f"{endpoint}?client_id={client_id}&state={state}&redirect_uri={redirect_uri}"

    async def exchange_code(self, token_endpoint, code, redirect_uri, code_verifier, client_id, client_secret, auth_method, resource):
        from app.core.tools.errors import OAuthFlowFailed

        if self.fail_exchange:
            raise OAuthFlowFailed("nope")
        return TokenSet(access_token=f"secret-access-{code}", refresh_token="secret-refresh", expires_in=3600, scopes=["read"])

    async def refresh(self, token_endpoint, refresh_token, client_id, client_secret, auth_method, resource):
        return TokenSet(access_token="refreshed", refresh_token=refresh_token, expires_in=3600)

    async def revoke(self, revocation_endpoint, token, client_id, client_secret, auth_method):
        self.revoked.append(token)


@pytest.fixture
def api():
    oauth = FakeOAuthFlow()
    h = make_harness(oauth=oauth)
    creds = InMemoryProjectCredentialRepository()
    app.dependency_overrides[get_tools_container] = lambda: h.container
    app.dependency_overrides[get_project_repository] = lambda: h.projects
    app.dependency_overrides[get_project_member_repository] = lambda: FakeMembers(h.project.id)
    app.dependency_overrides[get_credential_repository] = lambda: creds
    with TestClient(app, follow_redirects=False) as client:
        yield client, h, creds, oauth
    app.dependency_overrides.clear()


def create_integration(client, h: Harness, mode: str = "per_user") -> str:
    body = {
        "type": "mcp", "slug": "remote", "name": "Remote", "config": {"url": SERVER_URL},
        "auth_profile": {"auth_type": "oauth_authorization_code", "credential_mode": mode, "oauth": {"scopes": ["read"]}},
    }
    r = client.post(base(h) + "/integrations", json=body, headers=bearer("user_admin"))
    assert r.status_code == 201, r.text
    return r.json()["data"]["integration"]["id"]


def enable_policy(client, h: Harness) -> None:
    r = client.get(base(h) + "/tool-policy", headers=bearer("user_admin"))
    rev = r.json()["data"]["revision"]
    p = client.patch(
        base(h) + "/tool-policy", json={"revision": rev, "end_user_connect_enabled": True, "allowed_return_origins": [ORIGIN]},
        headers=bearer("user_admin"),
    )
    assert p.status_code == 200, p.text


def state_from(location: str) -> str:
    return parse_qs(urlparse(location).query)["state"][0]


def machine(h, creds, *scopes):
    return make_key(h, creds, list(scopes))


# ============================================================== public browser flow
def test_connect_link_to_callback_to_return_url_end_to_end(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    key = machine(h, creds, "connections:manage", "end_users:assert")

    link = client.post(base(h) + f"/integrations/{iid}/connect-links", json={"end_user_external_id": "cust_1", "return_url": RETURN}, headers=key)
    assert link.status_code == 201, link.text
    url = link.json()["data"]["connect_url"]
    assert url.startswith("https://api.axion.test/api/v1/integrations/connect/") and link.json()["data"]["expires_in"] == 900

    opened = client.get(urlparse(url).path)  # public: no credentials needed
    assert opened.status_code == 302 and opened.headers["location"].startswith("https://as.example.com/authorize?")
    state = state_from(opened.headers["location"])

    done = client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "abc"})
    assert done.status_code == 302
    target = done.headers["location"]
    assert target == f"{RETURN}?status=success&integration=remote"
    assert "abc" not in target and "secret" not in target

    reuse = client.get(urlparse(url).path)  # the link is single use
    assert reuse.status_code == 400 and reuse.json()["error"]["code"] == "CONNECT_SESSION_EXPIRED"
    replay = client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "abc"})
    assert replay.status_code == 302 and "error=connect_session_expired" in replay.headers["location"]


def test_callback_without_a_return_url_answers_with_an_outcome_only(api):
    client, h, creds, _ = api
    iid = create_integration(client, h, "project_shared")
    start = client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_admin"))
    assert start.status_code == 200
    state = state_from(start.json()["data"]["authorization_url"])
    ok = client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "c1"})
    assert ok.status_code == 200 and ok.json()["data"] == {"success": True, "integration": "remote", "error": None}
    assert "secret-access" not in ok.text and "c1" not in ok.text

    unknown = client.get("/api/v1/integrations/oauth/callback", params={"state": "bogus", "code": "x"})
    assert unknown.status_code == 200 and unknown.json()["data"]["error"] == "unknown_state"
    assert client.get("/api/v1/integrations/oauth/callback").json()["data"]["error"] == "invalid_request"
    denied_state = state_from(client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_admin")).json()["data"]["authorization_url"])
    denied = client.get("/api/v1/integrations/oauth/callback", params={"state": denied_state, "error": "access_denied", "error_description": "<script>"})
    assert denied.json()["data"]["error"] == "access_denied" and "script" not in denied.text  # provider text is never echoed


def test_failed_token_exchange_is_reported_without_internals(api):
    client, h, creds, oauth = api
    iid = create_integration(client, h, "project_shared")
    oauth.fail_exchange = True
    state = state_from(client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_admin")).json()["data"]["authorization_url"])
    r = client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "c"})
    assert r.json()["data"] == {"success": False, "integration": "remote", "error": "token_exchange_failed"}
    assert not h.connections_repo.items


def test_random_link_tokens_reveal_nothing(api):
    client, h, *_ = api
    r = client.get("/api/v1/integrations/connect/" + "x" * 43)
    assert r.status_code == 400 and r.json()["error"]["code"] == "CONNECT_SESSION_EXPIRED"


# ============================================================== roles & scopes
def test_authorize_roles_self_versus_project(api):
    client, h, *_ = api
    iid = create_integration(client, h, "project_shared")
    assert client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_member")).status_code == 403
    assert client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_viewer")).status_code == 403
    assert client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "project"}, headers=bearer("user_admin")).status_code == 200
    assert client.post(base(h) + f"/integrations/{iid}/oauth/authorize", headers={}).status_code == 401
    # A member asking for "self" on a shared integration is refused by the flow rules, not silently allowed.
    assert client.post(base(h) + f"/integrations/{iid}/oauth/authorize", json={"scope": "self"}, headers=bearer("user_member")).status_code == 400


def test_connect_links_need_admin_or_the_manage_scope_and_exactly_one_subject(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    path = base(h) + f"/integrations/{iid}/connect-links"
    assert client.post(path, json={"member_id": "user_member"}, headers=bearer("user_member")).status_code == 403
    assert client.post(path, json={"member_id": "user_member"}, headers=machine(h, creds, "tools:read")).status_code == 403
    assert client.post(path, json={"member_id": "user_member"}, headers=bearer("user_admin")).status_code == 201
    key = machine(h, creds, "connections:manage", "end_users:assert")
    assert client.post(path, json={}, headers=key).status_code == 400
    assert client.post(path, json={"member_id": "m", "end_user_external_id": "e"}, headers=key).status_code == 400
    assert client.post(path, json={"end_user_external_id": "cust_1", "return_url": "https://evil.example.com/x"}, headers=key).json()["error"]["code"] == "RETURN_URL_NOT_ALLOWED"


def test_admin_and_machine_can_list_and_revoke_connections_but_never_see_credentials(api):
    client, h, creds, oauth = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    key = machine(h, creds, "connections:manage", "end_users:assert")
    # Connect cust_1 through the real endpoints.
    url = client.post(base(h) + f"/integrations/{iid}/connect-links", json={"end_user_external_id": "cust_1"}, headers=key).json()["data"]["connect_url"]
    state = state_from(client.get(urlparse(url).path).headers["location"])
    client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "abc"})

    listing = client.get(base(h) + f"/integrations/{iid}/connections", headers=bearer("user_admin"))
    assert listing.status_code == 200 and listing.json()["data"]["pagination"]["total_records"] == 1
    item = listing.json()["data"]["items"][0]
    assert item["subject_type"] == "end_user" and item["status"] == "active" and item["credential_kind"] == "oauth"
    assert "secret-access" not in listing.text and "secret-refresh" not in listing.text and "envelope" not in listing.text.lower()
    assert client.get(base(h) + f"/integrations/{iid}/connections", headers=key).status_code == 200
    assert client.get(base(h) + f"/integrations/{iid}/connections", headers=bearer("user_member")).status_code == 403
    assert client.get(base(h) + f"/integrations/{iid}/connections", headers=machine(h, creds, "tools:read")).status_code == 403

    assert client.delete(base(h) + f"/integrations/{iid}/connections/{item['id']}", headers=bearer("user_member")).status_code == 403
    gone = client.delete(base(h) + f"/integrations/{iid}/connections/{item['id']}", headers=key)
    assert gone.status_code == 200 and oauth.revoked == ["secret-refresh"]  # revoked at the provider, then deleted
    assert client.delete(base(h) + f"/integrations/{iid}/connections/{item['id']}", headers=key).status_code == 404


def test_tool_policy_endpoints(api):
    client, h, creds, _ = api
    assert client.get(base(h) + "/tool-policy", headers=bearer("user_member")).status_code == 403
    assert client.get(base(h) + "/tool-policy", headers=machine(h, creds, "tools:read")).status_code == 403
    rev = client.get(base(h) + "/tool-policy", headers=bearer("user_admin")).json()["data"]["revision"]
    bad = client.patch(base(h) + "/tool-policy", json={"revision": rev, "allowed_return_origins": ["*"]}, headers=bearer("user_admin"))
    assert bad.status_code == 400
    ok = client.patch(base(h) + "/tool-policy", json={"revision": rev, "allowed_return_origins": ["https://App.Example.com/x"], "connect_link_ttl_seconds": 120}, headers=bearer("user_admin"))
    assert ok.json()["data"]["allowed_return_origins"] == [ORIGIN] and ok.json()["data"]["connect_link_ttl_seconds"] == 120
    stale = client.patch(base(h) + "/tool-policy", json={"revision": rev, "end_user_connect_enabled": True}, headers=bearer("user_admin"))
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "REVISION_CONFLICT"
    assert client.patch(base(h) + "/tool-policy", json={"revision": rev + 1, "connect_link_ttl_seconds": 5}, headers=bearer("user_admin")).status_code == 422


# ============================================================== self-service
def end_user_token(client, h, creds, external_id="cust_1", capabilities: Optional[list] = None) -> dict:
    key = machine(h, creds, "end_users:assert")
    body = {"capabilities": capabilities} if capabilities is not None else {}
    token = client.post(base(h) + f"/end-users/{external_id}/sessions", json=body, headers=key).json()["data"]["token"]
    return {"X-Axion-End-User-Token": token}


def test_end_users_manage_only_their_own_connections_with_a_session_token(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    ann, bob = end_user_token(client, h, creds, "cust_ann"), end_user_token(client, h, creds, "cust_bob")

    assert client.get(base(h) + "/me/connections", headers=ann).json()["data"] == []
    start = client.post(base(h) + f"/me/connections/{iid}/oauth", json={"return_url": RETURN}, headers=ann)
    assert start.status_code == 200, start.text
    state = state_from(start.json()["data"]["authorization_url"])
    assert client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "ann-code"}).status_code == 302

    mine = client.get(base(h) + "/me/connections", headers=ann).json()["data"]
    assert [(c["integration_slug"], c["status"], c["subject_type"]) for c in mine] == [("remote", "active", "end_user")]
    assert "secret-access" not in client.get(base(h) + "/me/connections", headers=ann).text
    assert client.get(base(h) + "/me/connections", headers=bob).json()["data"] == []  # Bob sees nothing of Ann's
    assert client.delete(base(h) + f"/me/connections/{iid}", headers=bob).json()["data"] == {"disconnected": False}
    assert client.delete(base(h) + f"/me/connections/{iid}", headers=ann).json()["data"] == {"disconnected": True}
    assert client.get(base(h) + "/me/connections", headers=ann).json()["data"] == []


def test_session_tokens_need_the_connections_capability_and_stop_working_when_blocked(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    apps_only = end_user_token(client, h, creds, "cust_x", capabilities=["apps:use"])
    assert client.get(base(h) + "/me/connections", headers=apps_only).status_code == 403
    assert client.post(base(h) + f"/me/connections/{iid}/oauth", headers=apps_only).status_code == 403

    token = end_user_token(client, h, creds, "cust_y")
    assert client.get(base(h) + "/me/connections", headers=token).status_code == 200
    client.post(base(h) + "/end-users/cust_y/block", headers=machine(h, creds, "end_users:manage"))
    assert client.get(base(h) + "/me/connections", headers=token).status_code == 403
    assert client.get(base(h) + "/me/connections", headers={"X-Axion-End-User-Token": "garbage"}).status_code == 401


def test_self_service_rejects_api_keys_and_anonymous_callers(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    assert client.get(base(h) + "/me/connections").status_code == 401
    key = machine(h, creds, "tools:read", "tools:invoke", "connections:manage", "end_users:assert")
    assert client.get(base(h) + "/me/connections", headers=key).status_code == 401  # an API key is not a user
    assert client.post(base(h) + f"/me/connections/{iid}/oauth", headers=key).status_code == 401
    assert client.get(base(h) + "/me/connections", headers=bearer("user_outsider")).status_code == 404


def test_members_use_the_same_self_service_endpoints_with_their_clerk_session(api):
    client, h, *_ = api
    iid = create_integration(client, h)
    assert client.get(base(h) + "/me/connections", headers=bearer("user_viewer")).status_code == 403  # viewers cannot connect
    start = client.post(base(h) + f"/me/connections/{iid}/oauth", headers=bearer("user_member"))
    assert start.status_code == 200
    state = state_from(start.json()["data"]["authorization_url"])
    assert client.get("/api/v1/integrations/oauth/callback", params={"state": state, "code": "m"}).status_code == 200
    mine = client.get(base(h) + "/me/connections", headers=bearer("user_member")).json()["data"]
    assert [c["subject_type"] for c in mine] == ["member"] and mine[0]["subject_id"] == "user_member"
    assert client.get(base(h) + "/me/connections", headers=bearer("user_admin")).json()["data"] == []  # not shared with the admin


def test_end_users_cannot_connect_until_the_project_enables_it_and_never_the_shared_credential(api):
    client, h, creds, _ = api
    iid = create_integration(client, h)
    ann = end_user_token(client, h, creds, "cust_ann")
    refused = client.post(base(h) + f"/me/connections/{iid}/oauth", headers=ann)
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "END_USER_CONNECT_DISABLED"

    shared = create_shared_second(client, h)
    enable_policy(client, h)
    assert client.post(base(h) + f"/me/connections/{shared}/oauth", headers=ann).status_code == 400  # shared: only admins connect it


def create_shared_second(client, h) -> str:
    body = {
        "type": "mcp", "slug": "shared", "name": "Shared", "config": {"url": "https://other.example.com/mcp"},
        "auth_profile": {"auth_type": "oauth_authorization_code", "credential_mode": "project_shared"},
    }
    r = client.post(base(h) + "/integrations", json=body, headers=bearer("user_admin"))
    assert r.status_code == 201, r.text
    return r.json()["data"]["integration"]["id"]


def test_a_shared_oauth_integration_waits_for_its_connection(api):
    client, h, *_ = api
    body = {
        "type": "mcp", "slug": "remote", "name": "Remote", "config": {"url": SERVER_URL},
        "auth_profile": {"auth_type": "oauth_authorization_code", "credential_mode": "project_shared"},
    }
    created = client.post(base(h) + "/integrations", json=body, headers=bearer("user_admin")).json()["data"]
    assert created["integration"]["status"] == "needs_auth"
    assert "connect" in created["warning"].lower() and created["discovery"] is None


# ============================================================== logging hygiene
def test_connect_link_secrets_never_reach_the_access_log(api, caplog):
    import logging

    client, h, creds, _ = api
    iid = create_integration(client, h)
    enable_policy(client, h)
    key = machine(h, creds, "connections:manage", "end_users:assert")
    url = client.post(base(h) + f"/integrations/{iid}/connect-links", json={"end_user_external_id": "cust_1"}, headers=key).json()["data"]["connect_url"]
    token = url.rsplit("/", 1)[1]

    with caplog.at_level(logging.DEBUG):
        client.get(urlparse(url).path)  # the browser opens the link
        client.get("/api/v1/integrations/oauth/callback", params={"state": "s", "code": "super-secret-code"})
    # Only the server's access logger counts: the TestClient's own httpx2 client logs the URLs *it* requests.
    logged = "\n".join(r.getMessage() for r in caplog.records if r.name == "app.http")
    assert "/integrations/connect/" in logged  # the request is still logged...
    assert token not in logged and "super-secret-code" not in logged  # ...without the secrets
    assert "[REDACTED]" in logged


def test_path_sanitizing_and_credential_route_redaction():
    from app.middleware.logging import is_redacted_path, sanitize_path

    assert sanitize_path("/api/v1/integrations/connect/abcDEF_123-xyz") == "/api/v1/integrations/connect/[REDACTED]"
    assert sanitize_path("/api/v1/projects/p/integrations") == "/api/v1/projects/p/integrations"
    assert is_redacted_path("/api/v1/projects/p/me/connections/i/credential")
    assert not is_redacted_path("/api/v1/projects/p/credentials")  # MOD-03 key listing is unaffected
