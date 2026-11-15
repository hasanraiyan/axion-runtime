"""
Credential resolution (SRS-07 FR-24, FR-28, FR-75): Gate 2.

Resolves credentials for ``(integration, subject)`` only. A ``per_user`` integration
never falls back to another subject's or the project's credential: without that
subject's own connection the call fails with ``AuthRequired``.
"""
from __future__ import annotations

from app.core.tools.ports import SecretReaderPort
from app.core.tools.registry import AuthStrategyRegistry
from app.core.tools.types import ResolvedCredentials, Subject
from app.models.integration import CredentialMode, Integration


class AuthRequired(Exception):
    """The subject has no usable connection for a ``per_user`` integration."""

    def __init__(self, integration: Integration, reason: str = "connection_required") -> None:
        super().__init__(reason)
        self.integration_id = str(integration.id)
        self.integration_slug = integration.slug
        self.reason = reason


class CredentialBuilder:
    def __init__(self, auth_registry: AuthStrategyRegistry, secrets: SecretReaderPort) -> None:
        self._registry = auth_registry
        self._secrets = secrets

    async def resolve(self, integration: Integration, subject: Subject) -> ResolvedCredentials:
        profile = integration.auth_profile
        if profile.credential_mode == CredentialMode.PER_USER:
            # Phase 2 introduces stored per-subject connections. Until a connection exists
            # for this subject there is nothing to use, and there is no shared fallback.
            raise AuthRequired(integration)
        strategy = self._registry.get(profile.auth_type)
        return await strategy.build(str(integration.project_id), profile, self._secrets)
