"""
Auth strategies (SRS-07 FR-24, FR-28): one class per auth type, selected via the
``AuthStrategyRegistry``. Strategies turn a declarative ``AuthProfile`` plus MOD-02
secrets into in-memory ``ResolvedCredentials``; they never persist or log plaintext.
"""
from __future__ import annotations

import base64
import re
from typing import List

from app.core.exceptions import BadRequestError
from app.core.tools.ports import SecretReaderPort
from app.core.tools.registry import AuthStrategyRegistry
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


class NoAuthStrategy:
    auth_type = AuthType.NONE

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        return ResolvedCredentials()


class ApiKeyStrategy:
    auth_type = AuthType.API_KEY

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)
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


class BearerStrategy:
    auth_type = AuthType.BEARER

    def validate(self, profile: AuthProfile) -> None:
        _require_shared(profile)
        _require_secret(profile, "bearer authentication")

    def secret_ids(self, profile: AuthProfile) -> List[str]:
        return [str(profile.secret_id)] if profile.secret_id else []

    def secret_names(self, profile: AuthProfile) -> List[str]:
        return []

    async def build(self, project_id: str, profile: AuthProfile, secrets: SecretReaderPort) -> ResolvedCredentials:
        token = await secrets.read(project_id, str(profile.secret_id))
        return ResolvedCredentials(headers={"Authorization": f"Bearer {token}"})


class BasicStrategy:
    auth_type = AuthType.BASIC

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


class CustomHeadersStrategy:
    auth_type = AuthType.CUSTOM_HEADERS

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


def build_default_auth_registry() -> AuthStrategyRegistry:
    registry = AuthStrategyRegistry()
    for strategy in (NoAuthStrategy(), ApiKeyStrategy(), BearerStrategy(), BasicStrategy(), CustomHeadersStrategy()):
        registry.register(strategy)
    return registry
