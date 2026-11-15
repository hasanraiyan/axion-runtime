"""
Credential resolution (SRS-07 FR-24, FR-28, FR-75): Gate 2.

Resolves credentials for ``(integration, subject)`` only. Static strategies build credentials from MOD-02
secrets; strategies that keep credentials in a stored connection (OAuth, or any ``per_user`` integration)
are resolved through the connection port. A ``per_user`` integration never falls back to another subject's
or the project's credential: without that subject's own connection the call fails with ``AuthRequired``.
"""
from __future__ import annotations

from typing import Optional

from app.core.tools.ports import ConnectionCredentialPort, SecretReaderPort
from app.core.tools.registry import AuthStrategyRegistry
from app.core.tools.types import ResolvedCredentials, Subject
from app.models.integration import CredentialMode, Integration


class AuthRequired(Exception):
    """The subject has no usable connection for this integration."""

    def __init__(self, integration: Integration, reason: str = "connection_required") -> None:
        super().__init__(reason)
        self.integration_id = str(integration.id)
        self.integration_slug = integration.slug
        self.reason = reason


class CredentialBuilder:
    def __init__(
        self,
        auth_registry: AuthStrategyRegistry,
        secrets: SecretReaderPort,
        connections: Optional[ConnectionCredentialPort] = None,
    ) -> None:
        self._registry = auth_registry
        self._secrets = secrets
        self._connections = connections

    async def resolve(self, integration: Integration, subject: Subject) -> ResolvedCredentials:
        profile = integration.auth_profile
        strategy = self._registry.get(profile.auth_type)
        if profile.credential_mode == CredentialMode.PER_USER or strategy.uses_connection:
            if self._connections is None:
                raise AuthRequired(integration)
            return await self._connections.credentials_for(integration, subject)
        return await strategy.build(str(integration.project_id), profile, self._secrets)
