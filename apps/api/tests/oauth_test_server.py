"""
In-process OAuth 2.1 authorization server + OAuth-protected MCP server for end-to-end tests.

One ASGI app serves: RFC 9728 protected-resource metadata, RFC 8414 server metadata, RFC 7591 dynamic
registration, ``/authorize`` (auto-approves as ``next_user``), ``/token`` (authorization_code with real PKCE
S256 verification, and rotating refresh_token), ``/revoke``, and an official-SDK MCP server on ``/mcp`` that only
accepts access tokens this server issued. No sockets, no network: the app is mounted on an
``httpx2.ASGITransport``. Counters and per-request records let tests assert exactly what happened.
"""
import asyncio
import base64
import hashlib
import json
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx2
from mcp.server.transport_security import TransportSecuritySettings

from tests.mcp_test_server import build_server

HOST = "https://mcp.example.com"
RESOURCE = f"{HOST}/mcp"


class OAuthMcpServer:
    def __init__(self) -> None:
        self.access_ttl = 3600
        self.next_user = "alice"
        self.deny_authorization = False
        self.fail_refresh: Optional[int] = None  # HTTP status for refresh failures (None = work)
        self.fail_refresh_error = "invalid_grant"
        self.refresh_delay = 0.0
        self.advertise_iss = False
        self.iss_value = HOST
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.codes: Dict[str, Dict[str, Any]] = {}
        self.access: Dict[str, Dict[str, Any]] = {}
        self.refresh: Dict[str, Dict[str, Any]] = {}
        self.counters = {"registrations": 0, "token": 0, "refresh": 0, "revocations": 0, "authorize": 0}
        self.mcp_requests: List[Dict[str, Any]] = []  # {"user": ..., "token": ...} per authenticated MCP request
        self.rejected_mcp = 0
        self._seq = 0
        self._mcp_app: Any = None
        self.transport: Optional[httpx2.ASGITransport] = None

    # ------------------------------------------------------------------ helpers
    def _next(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq}"

    @staticmethod
    async def _body(receive) -> bytes:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                return body

    @staticmethod
    async def _send(send, status: int, body: bytes = b"", headers: Optional[Dict[str, str]] = None, content_type: str = "application/json") -> None:
        raw = [(b"content-type", content_type.encode())] + [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        await send({"type": "http.response.start", "status": status, "headers": raw})
        await send({"type": "http.response.body", "body": body})

    async def _json(self, send, status: int, payload: Any, headers: Optional[Dict[str, str]] = None) -> None:
        await self._send(send, status, json.dumps(payload).encode(), headers)

    # ---------------------------------------------------------------- endpoints
    def _metadata(self) -> Dict[str, Any]:
        doc = {
            "issuer": HOST,
            "authorization_endpoint": f"{HOST}/authorize",
            "token_endpoint": f"{HOST}/token",
            "registration_endpoint": f"{HOST}/register",
            "revocation_endpoint": f"{HOST}/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        }
        if self.advertise_iss:
            doc["authorization_response_iss_parameter_supported"] = True
        return doc

    async def _register(self, receive, send) -> None:
        data = json.loads(await self._body(receive) or b"{}")
        self.counters["registrations"] += 1
        client_id = self._next("client")
        self.clients[client_id] = {"redirect_uris": data.get("redirect_uris", []), "secret": None}
        await self._json(send, 201, {**data, "client_id": client_id, "token_endpoint_auth_method": "none"})

    async def _authorize(self, query: Dict[str, str], send) -> None:
        self.counters["authorize"] += 1
        client = self.clients.get(query.get("client_id", ""))
        redirect = query.get("redirect_uri", "")
        problems = []
        if client is None or redirect not in client["redirect_uris"]:
            problems.append("unknown client or redirect_uri")
        if query.get("response_type") != "code" or query.get("code_challenge_method") != "S256" or not query.get("code_challenge"):
            problems.append("PKCE S256 required")
        if query.get("resource") != RESOURCE:
            problems.append("resource indicator missing or wrong")
        if not query.get("state"):
            problems.append("state required")
        if problems:
            await self._send(send, 400, "; ".join(problems).encode(), content_type="text/plain")
            return
        params: Dict[str, str] = {"state": query["state"]}
        if self.deny_authorization:
            params["error"] = "access_denied"
        else:
            code = self._next("code")
            self.codes[code] = {
                "client_id": query["client_id"], "redirect_uri": redirect, "challenge": query["code_challenge"],
                "user": self.next_user, "scope": query.get("scope", ""), "resource": query["resource"], "used": False,
            }
            params["code"] = code
        if self.advertise_iss:
            params["iss"] = self.iss_value
        await self._send(send, 302, headers={"location": f"{redirect}?{urlencode(params)}"})

    def _issue(self, user: str, client_id: str, scope: str) -> Dict[str, Any]:
        access, refresh = self._next("at"), self._next("rt")
        self.access[access] = {"user": user, "expires": time.time() + self.access_ttl, "revoked": False}
        self.refresh[refresh] = {"user": user, "client_id": client_id, "scope": scope, "used": False, "revoked": False}
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl, "refresh_token": refresh, "scope": scope}

    async def _token(self, receive, send) -> None:
        form = {k: v[0] for k, v in parse_qs((await self._body(receive)).decode()).items()}
        self.counters["token"] += 1
        grant = form.get("grant_type")
        if grant == "authorization_code":
            code = self.codes.get(form.get("code", ""))
            if code is None or code["used"]:
                return await self._json(send, 400, {"error": "invalid_grant"})
            code["used"] = True
            digest = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
            if (
                digest != code["challenge"] or form.get("client_id") != code["client_id"]
                or form.get("redirect_uri") != code["redirect_uri"] or form.get("resource") != code["resource"]
            ):
                return await self._json(send, 400, {"error": "invalid_grant"})
            return await self._json(send, 200, self._issue(code["user"], code["client_id"], code["scope"]))
        if grant == "refresh_token":
            self.counters["refresh"] += 1
            if self.refresh_delay:
                await asyncio.sleep(self.refresh_delay)
            if self.fail_refresh is not None:
                return await self._json(send, self.fail_refresh, {"error": self.fail_refresh_error})
            record = self.refresh.get(form.get("refresh_token", ""))
            if record is None or record["used"] or record["revoked"] or form.get("client_id") != record["client_id"]:
                return await self._json(send, 400, {"error": "invalid_grant"})
            record["used"] = True  # rotating refresh tokens
            return await self._json(send, 200, self._issue(record["user"], record["client_id"], record["scope"]))
        await self._json(send, 400, {"error": "unsupported_grant_type"})

    async def _revoke(self, receive, send) -> None:
        form = {k: v[0] for k, v in parse_qs((await self._body(receive)).decode()).items()}
        self.counters["revocations"] += 1
        token = form.get("token", "")
        if token in self.refresh:
            self.refresh[token]["revoked"] = True
            user = self.refresh[token]["user"]
            for info in self.access.values():
                if info["user"] == user:
                    info["revoked"] = True
        if token in self.access:
            self.access[token]["revoked"] = True
        await self._send(send, 200)

    # ----------------------------------------------------------------- dispatch
    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self._mcp_app(scope, receive, send)
        path, method = scope["path"], scope["method"]
        query = {k: v[0] for k, v in parse_qs(scope.get("query_string", b"").decode()).items()}

        if path == "/.well-known/oauth-protected-resource/mcp":
            return await self._json(send, 200, {"resource": RESOURCE, "authorization_servers": [HOST]})
        if path == "/.well-known/oauth-authorization-server":
            return await self._json(send, 200, self._metadata())
        if path == "/register" and method == "POST":
            return await self._register(receive, send)
        if path == "/authorize" and method == "GET":
            return await self._authorize(query, send)
        if path == "/token" and method == "POST":
            return await self._token(receive, send)
        if path == "/revoke" and method == "POST":
            return await self._revoke(receive, send)
        if path.startswith("/mcp"):
            return await self._guarded_mcp(scope, receive, send)
        await self._send(send, 404, b"not found", content_type="text/plain")

    async def _guarded_mcp(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        token = headers.get("authorization", "").removeprefix("Bearer ").strip()
        info = self.access.get(token)
        if info is None or info["revoked"] or info["expires"] <= time.time():
            self.rejected_mcp += 1
            challenge = f'Bearer resource_metadata="{HOST}/.well-known/oauth-protected-resource/mcp"'
            return await self._send(send, 401, b"unauthorized", {"www-authenticate": challenge}, "text/plain")
        self.mcp_requests.append({"user": info["user"], "token": token})
        await self._mcp_app(scope, receive, send)

    # ---------------------------------------------------------------- lifecycle
    @asynccontextmanager
    async def running(self) -> AsyncIterator["OAuthMcpServer"]:
        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        self._mcp_app = app
        async with app.router.lifespan_context(app):
            self.transport = httpx2.ASGITransport(app=self)
            yield self

    async def browser_authorize(self, authorization_url: str) -> Dict[str, str]:
        """Play the browser: GET the authorization URL, return the query parameters of the redirect."""
        async with httpx2.AsyncClient(transport=self.transport, follow_redirects=False) as client:
            response = await client.get(authorization_url)
        location = response.headers.get("location", "")
        assert response.status_code == 302, f"authorize failed: {response.status_code} {response.text}"
        return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}

    def tokens_used_by(self, user: str) -> List[str]:
        return [r["token"] for r in self.mcp_requests if r["user"] == user]
