"""
OAuth 2.1 flow client for MCP servers (SRS-07 FR-25, FR-26), implementing ``OAuthFlowPort``.

Uses the official MCP SDK's discovery and registration helpers (RFC 9728 protected-resource metadata,
RFC 8414 authorization-server metadata, RFC 7591 dynamic client registration, RFC 9207 issuer checks)
and adds only the steps the SDK does not expose as standalone calls: building the authorization URL,
the code exchange, refresh, and revocation. Every request goes through the Outbound Guard.
"""
from __future__ import annotations

import base64
import json
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlparse

import httpx2
from mcp.client.auth import utils as sdk
from mcp.shared.auth import OAuthClientMetadata, OAuthMetadata, OAuthToken

from app.core.outbound import OutboundUrlGuard
from app.core.tools.errors import OAuthFlowFailed, OAuthInvalidClient, OAuthInvalidGrant
from app.core.tools.oauth import DiscoveredOAuth, RegisteredClient, TokenSet, code_challenge_s256
from app.integrations.guarded_transport import GuardedAsyncTransport

REQUEST_TIMEOUT = 15.0


class OAuthFlowClient:
    def __init__(
        self,
        guard: OutboundUrlGuard,
        *,
        inner_transport: Optional[httpx2.AsyncBaseTransport] = None,
        pin_ips: bool = True,
    ) -> None:
        self._guard = guard
        self._inner = inner_transport
        self._pin = pin_ips

    def _client(self, allowed_hosts: Optional[List[str]] = None) -> httpx2.AsyncClient:
        transport = GuardedAsyncTransport(self._guard, allowed_hosts=allowed_hosts, inner=self._inner, pin_ips=self._pin)
        return httpx2.AsyncClient(transport=transport, timeout=REQUEST_TIMEOUT, follow_redirects=False)

    # ----------------------------------------------------------------- discovery
    async def discover(self, resource_url: str, allowed_hosts: Optional[List[str]] = None) -> DiscoveredOAuth:
        try:
            async with self._client(allowed_hosts) as client:
                prm = None
                for url in sdk.build_protected_resource_metadata_discovery_urls(None, resource_url):
                    response = await client.send(sdk.create_oauth_metadata_request(url))
                    prm = await sdk.handle_protected_resource_response(response)
                    if prm is not None:
                        break

                auth_server_url = str(prm.authorization_servers[0]) if prm and prm.authorization_servers else None
                metadata: Optional[OAuthMetadata] = None
                for url in sdk.build_oauth_authorization_server_metadata_discovery_urls(auth_server_url, resource_url):
                    response = await client.send(sdk.create_oauth_metadata_request(url))
                    proceed, metadata = await sdk.handle_auth_metadata_response(response)
                    if metadata is not None or not proceed:
                        break
        except OAuthFlowFailed:
            raise
        except Exception as exc:
            raise OAuthFlowFailed(f"OAuth discovery failed: {type(exc).__name__}") from exc

        if metadata is None:
            raise OAuthFlowFailed("The server does not publish OAuth authorization-server metadata")
        if "S256" not in (metadata.code_challenge_methods_supported or []):
            raise OAuthFlowFailed("The authorization server does not support PKCE (S256)")
        if auth_server_url:
            try:
                sdk.validate_metadata_issuer(metadata, auth_server_url)
            except Exception as exc:
                raise OAuthFlowFailed("The authorization server issuer does not match its metadata URL") from exc

        resource = str(prm.resource) if prm else resource_url
        if urlparse(resource).netloc.lower() != urlparse(resource_url).netloc.lower():
            raise OAuthFlowFailed("Protected-resource metadata describes a different resource")

        return DiscoveredOAuth(
            issuer=str(metadata.issuer),
            resource=resource,
            authorization_endpoint=str(metadata.authorization_endpoint),
            token_endpoint=str(metadata.token_endpoint),
            registration_endpoint=str(metadata.registration_endpoint) if metadata.registration_endpoint else None,
            revocation_endpoint=str(metadata.revocation_endpoint) if metadata.revocation_endpoint else None,
            scopes_supported=list(metadata.scopes_supported or (prm.scopes_supported if prm and prm.scopes_supported else [])),
            token_endpoint_auth_methods=list(metadata.token_endpoint_auth_methods_supported or []),
            iss_response_supported=bool(metadata.authorization_response_iss_parameter_supported),
        )

    # --------------------------------------------------------------- registration
    async def register_client(self, discovered: DiscoveredOAuth, redirect_uri: str, client_name: str) -> RegisteredClient:
        if not discovered.registration_endpoint:
            raise OAuthFlowFailed("The server does not support dynamic client registration; configure a client manually")
        metadata = OAuthClientMetadata(
            redirect_uris=[redirect_uri],
            token_endpoint_auth_method="none",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            client_name=client_name,
        )
        auth_metadata = OAuthMetadata.model_validate(
            {
                "issuer": discovered.issuer,
                "authorization_endpoint": discovered.authorization_endpoint,
                "token_endpoint": discovered.token_endpoint,
                "registration_endpoint": discovered.registration_endpoint,
            }
        )
        try:
            request = sdk.create_client_registration_request(auth_metadata, metadata, discovered.issuer)
            async with self._client() as client:
                response = await client.send(request)
            info = await sdk.handle_registration_response(response)
        except Exception as exc:
            raise OAuthFlowFailed(f"Dynamic client registration failed: {type(exc).__name__}") from exc
        return RegisteredClient(
            client_id=str(info.client_id),
            client_secret=info.client_secret,
            token_endpoint_auth_method=str(info.token_endpoint_auth_method or "none"),
        )

    # ------------------------------------------------------------- authorization
    def authorization_url(
        self,
        discovered_authorization_endpoint: str,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_verifier: str,
        scopes: List[str],
        resource: str,
    ) -> str:
        params: Dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge_s256(code_verifier),
            "code_challenge_method": "S256",
            "resource": resource,
        }
        if scopes:
            params["scope"] = " ".join(scopes)
        separator = "&" if "?" in discovered_authorization_endpoint else "?"
        return discovered_authorization_endpoint + separator + urlencode(params)

    # ------------------------------------------------------------------- tokens
    async def _token_request(
        self,
        token_endpoint: str,
        form: Dict[str, str],
        client_id: str,
        client_secret: Optional[str],
        auth_method: str,
    ) -> TokenSet:
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        body = dict(form)
        if auth_method == "client_secret_basic" and client_secret is not None:
            raw = f"{client_id}:{client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            body["client_id"] = client_id
            if auth_method == "client_secret_post" and client_secret is not None:
                body["client_secret"] = client_secret
        try:
            async with self._client() as client:
                response = await client.post(token_endpoint, content=urlencode(body), headers=headers)
        except Exception as exc:
            raise OAuthFlowFailed(f"Token request failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            error = ""
            try:
                error = str(json.loads(response.text).get("error", ""))
            except (ValueError, AttributeError):
                pass
            if error == "invalid_grant":
                raise OAuthInvalidGrant("The authorization grant is no longer valid")
            if error in ("invalid_client", "unauthorized_client"):
                raise OAuthInvalidClient("The authorization server rejected the OAuth client")
            raise OAuthFlowFailed(f"Token endpoint returned HTTP {response.status_code}" + (f" ({error[:60]})" if error else ""))
        try:
            token = OAuthToken.model_validate_json(response.text)
        except Exception as exc:
            raise OAuthFlowFailed("The token endpoint returned an invalid response") from exc
        return TokenSet(
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            expires_in=token.expires_in,
            scopes=token.scope.split() if token.scope else [],
            token_type=token.token_type or "Bearer",
        )

    async def exchange_code(
        self,
        token_endpoint: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        client_id: str,
        client_secret: Optional[str],
        auth_method: str,
        resource: str,
    ) -> TokenSet:
        return await self._token_request(
            token_endpoint,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                "resource": resource,
            },
            client_id,
            client_secret,
            auth_method,
        )

    async def refresh(
        self,
        token_endpoint: str,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str],
        auth_method: str,
        resource: str,
    ) -> TokenSet:
        return await self._token_request(
            token_endpoint,
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "resource": resource},
            client_id,
            client_secret,
            auth_method,
        )

    async def client_credentials(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        auth_method: str,
        scopes: List[str],
        resource: Optional[str],
    ) -> TokenSet:
        form: Dict[str, str] = {"grant_type": "client_credentials"}
        if scopes:
            form["scope"] = " ".join(scopes)
        if resource:
            form["resource"] = resource
        return await self._token_request(token_endpoint, form, client_id, client_secret, auth_method)

    async def revoke(
        self,
        revocation_endpoint: Optional[str],
        token: str,
        client_id: str,
        client_secret: Optional[str],
        auth_method: str,
    ) -> None:
        """Best-effort RFC 7009 revocation; never raises (disconnecting must always succeed locally)."""
        if not revocation_endpoint:
            return
        try:
            await self._token_request_raw(revocation_endpoint, {"token": token}, client_id, client_secret, auth_method)
        except Exception:
            return

    async def _token_request_raw(self, endpoint: str, form: Dict[str, str], client_id: str, client_secret: Optional[str], auth_method: str) -> None:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = dict(form)
        if auth_method == "client_secret_basic" and client_secret is not None:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
        else:
            body["client_id"] = client_id
            if client_secret is not None and auth_method == "client_secret_post":
                body["client_secret"] = client_secret
        async with self._client() as client:
            await client.post(endpoint, content=urlencode(body), headers=headers)
