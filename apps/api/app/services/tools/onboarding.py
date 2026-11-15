"""
IntegrationOnboardingService (SRS-07 FR-01 steps 5-6): create, then test, then discover.

A thin orchestrator over ``IntegrationService``, ``IntegrationHealthService`` and
``DiscoveryService`` so each of those keeps a single responsibility. A failed test or discovery
does not undo creation: the integration is kept in ``error`` with the reason, ready to fix and retry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import AppException
from app.core.tools.types import ProbeResult
from app.models.integration import CredentialMode, Integration
from app.schemas.tools import IntegrationCreateRequest
from app.services.tools.discovery_service import DiscoveryService, DiscoverySummary
from app.services.tools.health_service import IntegrationHealthService
from app.services.tools.integration_service import IntegrationService

IdLike = Union[str, PydanticObjectId, ObjectId]


@dataclass
class OnboardingResult:
    integration: Integration
    probe: Optional[ProbeResult] = None
    discovery: Optional[DiscoverySummary] = None
    warning: Optional[str] = None


class IntegrationOnboardingService:
    def __init__(
        self,
        integrations: IntegrationService,
        health: IntegrationHealthService,
        discovery: DiscoveryService,
    ) -> None:
        self._integrations = integrations
        self._health = health
        self._discovery = discovery

    async def verify(self, project_id: IdLike, integration_id: IdLike, actor_id: str) -> OnboardingResult:
        """Test and discover an existing integration (used after a project connection is made)."""
        integration, probe = await self._health.test(project_id, integration_id, actor_id)
        result = OnboardingResult(integration=integration, probe=probe)
        if probe.healthy:
            result.discovery = await self._discovery.discover(project_id, integration_id, actor_id)
        else:
            result.warning = probe.message
        return result

    async def create_and_verify(
        self, project_id: IdLike, request: IntegrationCreateRequest, actor_id: str
    ) -> OnboardingResult:
        integration = await self._integrations.create(project_id, request, actor_id)
        result = OnboardingResult(integration=integration)

        if integration.auth_profile.credential_mode == CredentialMode.PER_USER:
            result.warning = "Connect your own account, then run discovery, to make this per-user integration available"
            return result

        try:
            integration, probe = await self._health.test(integration.project_id, integration.id, actor_id)
            result.integration, result.probe = integration, probe
            if probe.healthy:
                result.discovery = await self._discovery.discover(integration.project_id, integration.id, actor_id)
                refreshed, _ = await self._integrations.list(integration.project_id, search=integration.slug, limit=1)
                if refreshed:
                    result.integration = refreshed[0]
            else:
                result.warning = probe.message or "The integration could not be reached"
        except AppException as exc:
            result.warning = exc.message
        return result
