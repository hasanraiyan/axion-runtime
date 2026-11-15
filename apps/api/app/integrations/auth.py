"""
Auth strategies (SRS-07 FR-24, FR-28): one class per auth type, selected via the
``AuthStrategyRegistry``. Strategies turn a declarative ``AuthProfile`` plus MOD-02
secrets into in-memory ``ResolvedCredentials``; they never persist or log plaintext.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import List, Optional
from urllib.parse import urlsplit

from app.core.exceptions import BadRequestError
from app.core.tools.errors import OAuthFlowFailed, OAuthInvalidClient, UpstreamAuthError, UpstreamError
from app.core.tools.ports import ClientCredentialsPort, SecretReaderPort
from app.core.tools.registry import AuthStrategyRegistry
from app.core.tools.telemetry import NullTelemetry, TelemetryPort
from app.core.tools.token_cache import TokenCache
from app.core.tools.types import ResolvedCredentials
from app.models.integration import AuthProfile, AuthType, CredentialMode
from app.core.secret_templates import SecretTemplateParser

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$")
_FORBIDDEN_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "mcp-session-id",
}


def _require_shared(profile: AuthProfile) -> None:
    if profile.credential_mode != CredentialMode.PROJECT_SHARED:
        raise BadRequestError(
            "per_user credential mode requires the user connection flow, which is not available for this "
            "integration yet; use project_shared"
        )


def _require_secret(profile: AuthProfile, label: str) -> str:
    if profile.secret_id is None:
        raise BadRequestError(f"{label} requires a secret_id")
    return str(profile.secret_id)


def _validate_header_name(name: str) -> str:
    if not _HEADER_NAME.match(name) or name.lower() in _FORBIDDEN_HEADERS:
        raise BadRequestError(f"Header name '{name[:50]}' is not allowed")
    return name


class _Local:
    """Defaults for strategies that make no network calls and cache nothing."""

    def target_urls(self, profile: AuthProfile) -> List[str]:
        return []

    def forget(self, project_id: str, profile: AuthProfile) -> bool:
        return False


class NoAuthStrategy(_Local):
    auth_type = AuthType.NONE
    uses_connection = False
    static_kind = None

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        return ResolvedCredentials()


class ApiKeyStrategy(_Local):
    auth_type = AuthType.API_KEY
    uses_connection = False
    static_kind = 'api_key'

    def validate(self, profile: AuthProfile) -> None:
        if profile.credential_mode == CredentialMode.PROJECT_SHARED:
            _require_secret(profile, "api_key authentication")
        placement = profile.placement or "header"
        name = profile.name or ("X-API-Key" if placement == "header" else None)
        if not name:
            raise BadRequestError("api_key authentication in a query string requires a parameter name")
        if placement == "header":
            _validate_header_name(name)

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        value = f"{profile.prefix or ''}{await secrets.read(project_id, str(profile.secret_id))}"
        placement = profile.placement or "header"
        name = profile.name or "X-API-Key"
        if placement == "query":
            return ResolvedCredentials(query={name: value})
        return ResolvedCredentials(headers={name: value})


class BearerStrategy(_Local):
    auth_type = AuthType.BEARER
    uses_connection = False
    static_kind = 'bearer'

    def validate(self, profile: AuthProfile) -> None:
        if profile.credential_mode == CredentialMode.PROJECT_SHARED:
            _require_secret(profile, "bearer authentication")

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        token = await secrets.read(project_id, str(profile.secret_id))
        return ResolvedCredentials(headers={"Authorization": f"Bearer {token}"})


class BasicStrategy(_Local):
    auth_type = AuthType.BASIC
    uses_connection = False
    static_kind = None

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)
        _require_secret(profile, "basic authentication (password secret)")
        if not profile.username:
            raise BadRequestError("basic authentication requires a username")
        if ":" in profile.username:
            raise BadRequestError("basic authentication usernames must not contain ':'")

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        password = await secrets.read(project_id, str(profile.secret_id))
        raw = f"{profile.username}:{password}".encode("utf-8")
        return ResolvedCredentials(headers={"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"})


class CustomHeadersStrategy(_Local):
    auth_type = AuthType.CUSTOM_HEADERS
    uses_connection = False
    static_kind = None

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)
        if not profile.headers:
            raise BadRequestError("custom_headers authentication requires at least one header")
        if len(profile.headers) > 20:
            raise BadRequestError("custom_headers supports at most 20 headers")
        for name, value in profile.headers.items():
            _validate_header_name(name)
            if "\r" in value or "\n" in value or len(value) > 2000:
                raise BadRequestError(f"Header '{name}' has an invalid value")

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return []  # referenced by name through {{secrets.NAME}} templates

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        headers = {}
        for name, template in profile.headers.items():
            resolved = {}
            for placeholder in SecretTemplateParser.extract_placeholders(template):
                value = await secrets.read_by_name(project_id, placeholder)
                if value is None:
                    raise BadRequestError(f"Secret '{placeholder}' referenced by header '{name}' was not found")
                resolved[placeholder] = value
            rendered = SecretTemplateParser.interpolate(template, resolved)
            if "\r" in rendered or "\n" in rendered:
                raise BadRequestError(f"Header '{name}' resolved to an invalid value")
            headers[name] = rendered
        return ResolvedCredentials(headers=headers)

    def secret_names(self, profile: AuthProfile) -> List[str]:
        names: set[str] = set()
        for template in profile.headers.values():
            names.update(SecretTemplateParser.extract_placeholders(template))
        return sorted(names)


class OAuthAuthorizationCodeStrategy(_Local):
    """OAuth 2.1 authorization code + PKCE (MCP). Tokens live in a stored connection, never in the profile."""

    auth_type = AuthType.OAUTH_AUTHORIZATION_CODE
    uses_connection = True
    static_kind = None

    def validate(self, profile: AuthProfile) -> None:
        oauth = profile.oauth or {}
        scopes = oauth.get("scopes", [])
        if not isinstance(scopes, list) or len(scopes) > 50 or not all(isinstance(s, str) and 0 < len(s) <= 200 for s in scopes):
            raise BadRequestError("oauth.scopes must be a list of up to 50 scope strings")
        client_id = oauth.get("client_id")
        if client_id is not None and (not isinstance(client_id, str) or not client_id or len(client_id) > 500):
            raise BadRequestError("oauth.client_id must be a non-empty string")
        if profile.secret_id is not None and not client_id:
            raise BadRequestError("A client secret requires oauth.client_id")
        unknown = set(oauth) - {"scopes", "client_id"}
        if unknown:
            raise BadRequestError(f"Unsupported oauth setting: {sorted(unknown)[0]}")

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []  # the optional manual client secret

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        raise BadRequestError("OAuth credentials come from a stored connection")


CLIENT_CREDENTIALS_AUTH_METHODS = ("client_secret_basic", "client_secret_post")


class OAuthClientCredentialsStrategy:
    """
    OAuth 2.0 client credentials (machine-to-machine). The client secret is a MOD-02 secret; the token endpoint is
    explicit (there is no user to redirect, so nothing is discovered) and is checked by the Outbound Guard when the
    integration is saved. Tokens are cached in memory only and never persisted. Always ``project_shared``: a client
    credential identifies the project's application, not a person.
    """

    auth_type = AuthType.OAUTH_CLIENT_CREDENTIALS
    uses_connection = False
    static_kind = None

    def __init__(
        self, flow: ClientCredentialsPort, cache: Optional[TokenCache] = None, telemetry: Optional[TelemetryPort] = None
    ) -> None:
        self._telemetry: TelemetryPort = telemetry or NullTelemetry()
        self._flow = flow
        self._cache = cache if cache is not None else TokenCache()

    # ---------------------------------------------------------------- validation
    def validate(self, profile: AuthProfile) -> None:
        if profile.credential_mode != CredentialMode.PROJECT_SHARED:
            raise BadRequestError("oauth_client_credentials identifies the project's application and must use project_shared")
        _require_secret(profile, "oauth_client_credentials (client secret)")
        oauth = profile.oauth or {}
        unknown = set(oauth) - {"client_id", "token_endpoint", "scopes", "resource", "token_endpoint_auth_method"}
        if unknown:
            raise BadRequestError(f"Unsupported oauth setting: {sorted(unknown)[0]}")
        client_id = oauth.get("client_id")
        if not isinstance(client_id, str) or not client_id or len(client_id) > 500:
            raise BadRequestError("oauth.client_id is required")
        self._token_endpoint(oauth)
        scopes = oauth.get("scopes", [])
        if not isinstance(scopes, list) or len(scopes) > 50 or not all(isinstance(x, str) and 0 < len(x) <= 200 for x in scopes):
            raise BadRequestError("oauth.scopes must be a list of up to 50 scope strings")
        resource = oauth.get("resource")
        if resource is not None:
            parts = urlsplit(resource) if isinstance(resource, str) else None
            if parts is None or parts.scheme not in ("http", "https") or not parts.netloc or len(resource) > 2000:
                raise BadRequestError("oauth.resource must be an absolute http(s) URL")
        method = oauth.get("token_endpoint_auth_method", "client_secret_basic")
        if method not in CLIENT_CREDENTIALS_AUTH_METHODS:
            raise BadRequestError(f"oauth.token_endpoint_auth_method must be one of {', '.join(CLIENT_CREDENTIALS_AUTH_METHODS)}")

    @staticmethod
    def _token_endpoint(oauth: dict) -> str:
        endpoint = oauth.get("token_endpoint")
        parts = urlsplit(endpoint) if isinstance(endpoint, str) else None
        if parts is None or parts.scheme != "https" or not parts.hostname or parts.username or parts.fragment or len(endpoint) > 2000:
            raise BadRequestError("oauth.token_endpoint is required and must be an https URL")
        return endpoint

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    def target_urls(self, profile: AuthProfile) -> List[str]:
        return [self._token_endpoint(profile.oauth or {})]

    # --------------------------------------------------------------------- tokens
    @staticmethod
    def _key(project_id: str, profile: AuthProfile) -> tuple:
        oauth = profile.oauth or {}
        return (
            project_id,
            str(profile.secret_id),
            oauth.get("client_id"),
            oauth.get("token_endpoint"),
            tuple(sorted(oauth.get("scopes", []))),
            oauth.get("resource"),
            oauth.get("token_endpoint_auth_method", "client_secret_basic"),
        )

    def forget(self, project_id: str, profile: AuthProfile) -> bool:
        return self._cache.invalidate(self._key(project_id, profile))

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        oauth = profile.oauth or {}
        client_secret = await secrets.read(project_id, str(profile.secret_id))
        fingerprint = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        async def fetch():
            try:
                tokens = await self._flow.client_credentials(
                    self._token_endpoint(oauth),
                    oauth["client_id"],
                    client_secret,
                    oauth.get("token_endpoint_auth_method", "client_secret_basic"),
                    list(oauth.get("scopes", [])),
                    oauth.get("resource"),
                )
                self._telemetry.count("axion_oauth_token_requests_total", {"grant": "client_credentials", "outcome": "ok"})
                return tokens
            except OAuthInvalidClient as exc:
                self._telemetry.count("axion_oauth_token_requests_total", {"grant": "client_credentials", "outcome": "rejected"})
                raise UpstreamAuthError("The authorization server rejected the OAuth client credentials") from exc
            except OAuthFlowFailed as exc:
                self._telemetry.count("axion_oauth_token_requests_total", {"grant": "client_credentials", "outcome": "error"})
                raise UpstreamError(str(exc)) from exc

        token = await self._cache.get(self._key(project_id, profile), fingerprint, fetch)
        return ResolvedCredentials(headers={"Authorization": f"Bearer {token}"})


def build_default_auth_registry(
    flow: Optional[ClientCredentialsPort] = None,
    token_cache: Optional[TokenCache] = None,
    telemetry: Optional[TelemetryPort] = None,
) -> AuthStrategyRegistry:
    registry = AuthStrategyRegistry()
    strategies = [
        NoAuthStrategy(),
        ApiKeyStrategy(),
        BearerStrategy(),
        BasicStrategy(),
        CustomHeadersStrategy(),
        OAuthAuthorizationCodeStrategy(),
    ]
    if flow is not None:  # machine-to-machine OAuth needs a way to reach the token endpoint
        strategies.append(OAuthClientCredentialsStrategy(flow, token_cache, telemetry))
    for strategy in strategies:
        registry.register(strategy)
    return registry
