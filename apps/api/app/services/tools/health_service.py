"""IntegrationHealthService (SRS-07 FR-04, FR-38): probes, status mapping, breaker-driven state."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Union

from beanie import PydanticObjectId
from bson import ObjectId

from app.core.exceptions import BadRequestError, NotFoundError
from app.core.protocols.tool_repositories import IIntegrationRepository
from app.core.tools.events import ToolsetChanged
from app.core.tools.ports import AuditPort, DomainEventPort, HealthProber, supports
from app.core.tools.registry import AdapterRegistry
from app.core.tools.types import ProbeResult, Subject, SubjectType
from app.models.integration import Integration, IntegrationStatus
from app.models.project import ProjectAuditAction
from app.services.tools.common import ProjectLifecycle
from app.services.tools.credentials import AuthRequired, CredentialBuilder

IdLike = Union[str, PydanticObjectId, ObjectId]

_STATUS_FOR_PROBE: Dict[str, IntegrationStatus] = {
    "healthy": IntegrationStatus.ACTIVE,
    "rate_limited": IntegrationStatus.DEGRADED,
    "auth_failed": IntegrationStatus.ERROR,
    "unreachable": IntegrationStatus.ERROR,
}


class IntegrationHealthService:
    def __init__(
        self,
        lifecycle: ProjectLifecycle,
        integration_repo: IIntegrationRepository,
        adapters: AdapterRegistry,
        credentials: CredentialBuilder,
        audit: AuditPort,
        events: DomainEventPort,
    ) -> None:
        self._lifecycle = lifecycle
        self._integrations = integration_repo
        self._adapters = adapters
        self._credentials = credentials
        self._audit = audit
        self._events = events

    async def test(self, project_id: IdLike, integration_id: IdLike, actor_id: str) -> tuple[Integration, ProbeResult]:
        project = await self._lifecycle.get_active(project_id)
        integration = await self._integrations.get_by_id_and_project(integration_id, project.id)
        if integration is None:
            raise NotFoundError(f"Integration '{integration_id}' not found")
        adapter = self._adapters.for_integration(integration)
        if not supports(adapter, HealthProber):
            raise BadRequestError("This integration type does not support connection tests")

        try:
            credentials = await self._credentials.resolve(integration, Subject(SubjectType.PROJECT))
            result = await adapter.probe(integration, credentials)
        except AuthRequired:
            result = ProbeResult(healthy=True, status="healthy", message="Per-user integration; no shared credential to test")
            status = integration.status
        else:
            status = _STATUS_FOR_PROBE.get(result.status, IntegrationStatus.ERROR)

        if not integration.is_enabled:
            status = IntegrationStatus.DISABLED
        health = {
            "status": result.status,
            "latency_ms": result.latency_ms,
            "checked_at": datetime.now(timezone.utc),
            "message": result.message,
        }
        await self._integrations.update_runtime_state(
            integration.id,
            project.id,
            {
                "status": status,
                "status_reason": None if result.healthy else result.message,
                "health": health,
                "consecutive_failures": 0 if result.healthy else integration.consecutive_failures,
            },
        )
        await self._audit.record(
            str(project.id),
            actor_id,
            ProjectAuditAction.INTEGRATION_TESTED.value,
            {"integration_id": str(integration.id), "result": result.status},
        )
        await self._events.publish(ToolsetChanged(str(project.id), "integration_tested"))
        refreshed = await self._integrations.get_by_id_and_project(integration.id, project.id)
        return (refreshed or integration), result

    async def mark_degraded(self, integration: Integration, reason: str) -> None:
        """Called by the Gateway when its breaker opens (FR-38)."""
        await self._integrations.update_runtime_state(
            integration.id,
            integration.project_id,
            {"status": IntegrationStatus.DEGRADED, "status_reason": reason[:500]},
        )
        await self._events.publish(ToolsetChanged(str(integration.project_id), "integration_degraded"))

    async def mark_recovered(self, integration: Integration) -> None:
        if integration.status == IntegrationStatus.DEGRADED:
            await self._integrations.update_runtime_state(
                integration.id,
                integration.project_id,
                {"status": IntegrationStatus.ACTIVE, "status_reason": None, "consecutive_failures": 0},
            )
            await self._events.publish(ToolsetChanged(str(integration.project_id), "integration_recovered"))

    async def mark_error(self, integration: Integration, reason: str) -> None:
        """Called by the Gateway when upstream rejects the integration's credentials."""
        await self._integrations.update_runtime_state(
            integration.id,
            integration.project_id,
            {"status": IntegrationStatus.ERROR, "status_reason": reason[:500]},
        )
        await self._events.publish(ToolsetChanged(str(integration.project_id), "integration_error"))
