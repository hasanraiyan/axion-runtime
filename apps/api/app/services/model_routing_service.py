"""
Model Routing Service implementing resilient multi-provider failover chains,
routing policy management, and dynamic model execution resolution (SRS-06 FR-07).
"""
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends

from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ProjectArchivedError,
    ProjectDeletedError,
    ProjectPurgedError,
)
from app.core.protocols.repositories import (
    IProjectAuditRepository,
    IProjectModelRepository,
    IProjectProviderRepository,
    IProjectRepository,
    IProjectRoutingPolicyRepository,
)
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectStatus,
)
from app.models.project_provider import ProviderStatus
from app.models.project_routing_policy import ProjectRoutingPolicy
from app.repositories.project_audit_repository import (
    ProjectAuditRepository,
    get_project_audit_repository,
)
from app.repositories.project_model_repository import (
    ProjectModelRepository,
    get_project_model_repository,
)
from app.repositories.project_provider_repository import (
    ProjectProviderRepository,
    get_project_provider_repository,
)
from app.repositories.project_repository import (
    ProjectRepository,
    get_project_repository,
)
from app.repositories.project_routing_policy_repository import (
    ProjectRoutingPolicyRepository,
    get_project_routing_policy_repository,
)
from app.schemas.routing_policy import (
    ModelResolutionRequest,
    ModelResolutionResponse,
    RoutingPolicyCreateRequest,
    RoutingPolicyResponse,
    RoutingPolicyUpdateRequest,
)


class ModelRoutingService:
    """
    Domain service orchestrating model routing policies and dynamic failover resolution.
    """

    def __init__(
        self,
        routing_policy_repo: Optional[IProjectRoutingPolicyRepository] = None,
        model_repo: Optional[IProjectModelRepository] = None,
        provider_repo: Optional[IProjectProviderRepository] = None,
        project_repo: Optional[IProjectRepository] = None,
        audit_repo: Optional[IProjectAuditRepository] = None,
    ) -> None:
        self.routing_policy_repo = (
            routing_policy_repo if routing_policy_repo is not None else get_project_routing_policy_repository()
        )
        self.model_repo = model_repo if model_repo is not None else get_project_model_repository()
        self.provider_repo = provider_repo if provider_repo is not None else get_project_provider_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()

    async def _get_active_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        allow_archived: bool = False,
    ) -> Project:
        """Validate project existence and lifecycle state."""
        project = await self.project_repo.get_by_id_or_slug(project_id)
        if not project:
            raise NotFoundError(f"Project '{project_id}' not found")
        if project.status == ProjectStatus.PURGED:
            raise ProjectPurgedError(str(project.id))
        if project.status == ProjectStatus.SOFT_DELETED:
            raise ProjectDeletedError(str(project.id))
        if project.status == ProjectStatus.ARCHIVED and not allow_archived:
            raise ProjectArchivedError(str(project.id))
        return project

    async def create_policy(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: RoutingPolicyCreateRequest,
        actor_id: str,
    ) -> RoutingPolicyResponse:
        """
        Create a new routing policy with primary and ordered backup candidates (FR-07).
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        # Check unique policy name within project
        existing_name = await self.routing_policy_repo.get_by_name(project.id, request.name)
        if existing_name:
            raise ConflictError(f"Routing policy with name '{request.name}' already exists in this project")

        # Validate primary model existence
        primary_model = await self.model_repo.get_by_id_and_project(request.primary_model_id, project.id)
        if not primary_model:
            raise NotFoundError(f"Primary model '{request.primary_model_id}' not found in project")

        # Validate fallback model existence
        fallback_ids: List[PydanticObjectId] = []
        for fid in request.fallback_model_ids:
            fb_model = await self.model_repo.get_by_id_and_project(fid, project.id)
            if not fb_model:
                raise NotFoundError(f"Fallback model '{fid}' not found in project")
            fallback_ids.append(PydanticObjectId(fid))

        policy_doc = ProjectRoutingPolicy(
            project_id=project.id,
            name=request.name,
            description=request.description,
            primary_model_id=PydanticObjectId(request.primary_model_id),
            fallback_model_ids=fallback_ids,
            retry_timeout_ms=request.retry_timeout_ms,
            fallback_on_codes=request.fallback_on_codes,
            is_active=request.is_active,
            revision=1,
        )

        created = await self.routing_policy_repo.create(policy_doc)

        return RoutingPolicyResponse.from_model(created)

    async def get_policy(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        policy_id: Union[str, PydanticObjectId, ObjectId],
    ) -> RoutingPolicyResponse:
        """Fetch routing policy by ID."""
        project = await self._get_active_project(project_id, allow_archived=True)
        policy = await self.routing_policy_repo.get_by_id_and_project(policy_id, project.id)
        if not policy:
            raise NotFoundError(f"Routing policy '{policy_id}' not found")
        return RoutingPolicyResponse.from_model(policy)

    async def list_policies(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        is_active: Optional[bool] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[RoutingPolicyResponse], int]:
        """List routing policies scoped to project."""
        project = await self._get_active_project(project_id, allow_archived=True)
        policies, total = await self.routing_policy_repo.list_by_project(
            project_id=project.id,
            is_active=is_active,
            skip=skip,
            limit=limit,
        )
        return [RoutingPolicyResponse.from_model(p) for p in policies], total

    async def update_policy(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        policy_id: Union[str, PydanticObjectId, ObjectId],
        request: RoutingPolicyUpdateRequest,
        actor_id: str,
    ) -> RoutingPolicyResponse:
        """Atomically update routing policy enforcing OCC revision counter."""
        project = await self._get_active_project(project_id, allow_archived=False)
        existing = await self.routing_policy_repo.get_by_id_and_project(policy_id, project.id)
        if not existing:
            raise NotFoundError(f"Routing policy '{policy_id}' not found")

        update_dict: Dict[str, Any] = {}
        if request.name is not None:
            update_dict["name"] = request.name
        if request.description is not None:
            update_dict["description"] = request.description
        if request.primary_model_id is not None:
            p_model = await self.model_repo.get_by_id_and_project(request.primary_model_id, project.id)
            if not p_model:
                raise NotFoundError(f"Primary model '{request.primary_model_id}' not found")
            update_dict["primary_model_id"] = PydanticObjectId(request.primary_model_id)
        if request.fallback_model_ids is not None:
            fb_ids = []
            for fid in request.fallback_model_ids:
                f_model = await self.model_repo.get_by_id_and_project(fid, project.id)
                if not f_model:
                    raise NotFoundError(f"Fallback model '{fid}' not found")
                fb_ids.append(PydanticObjectId(fid))
            update_dict["fallback_model_ids"] = fb_ids
        if request.retry_timeout_ms is not None:
            update_dict["retry_timeout_ms"] = request.retry_timeout_ms
        if request.fallback_on_codes is not None:
            update_dict["fallback_on_codes"] = request.fallback_on_codes
        if request.is_active is not None:
            update_dict["is_active"] = request.is_active

        updated = await self.routing_policy_repo.update_with_revision(
            policy_id=existing.id,
            project_id=project.id,
            expected_revision=request.revision,
            update_dict=update_dict,
        )

        return RoutingPolicyResponse.from_model(updated)

    async def delete_policy(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        policy_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> bool:
        """Delete routing policy."""
        project = await self._get_active_project(project_id, allow_archived=False)
        existing = await self.routing_policy_repo.get_by_id_and_project(policy_id, project.id)
        if not existing:
            raise NotFoundError(f"Routing policy '{policy_id}' not found")

        return await self.routing_policy_repo.delete(existing.id, project.id)

    async def resolve_model(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: ModelResolutionRequest,
        actor_id: Optional[str] = None,
    ) -> ModelResolutionResponse:
        """
        Dynamically resolve model candidate with resilient fallback (FR-07).
        First checks if model_identifier refers to a RoutingPolicy; otherwise resolves directly.
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        # 1. Check if model_identifier matches a routing policy (by name or ID)
        policy: Optional[ProjectRoutingPolicy] = None
        policy = await self.routing_policy_repo.get_by_name(project.id, request.model_identifier)
        if not policy:
            try:
                policy = await self.routing_policy_repo.get_by_id_and_project(request.model_identifier, project.id)
            except Exception:
                policy = None

        if policy and policy.is_active:
            # Evaluate primary candidate
            primary_model = await self.model_repo.get_by_id_and_project(policy.primary_model_id, project.id)
            primary_provider = (
                await self.provider_repo.get_by_id_and_project(primary_model.provider_id, project.id)
                if primary_model
                else None
            )

            primary_healthy = (
                primary_model is not None
                and primary_model.is_enabled
                and primary_provider is not None
                and primary_provider.status == ProviderStatus.ACTIVE
            )

            if primary_healthy and primary_model and primary_provider:
                return ModelResolutionResponse(
                    model_id=str(primary_model.id),
                    upstream_model_id=primary_model.model_id,
                    display_name=primary_model.display_name,
                    provider_id=str(primary_provider.id),
                    provider_type=primary_provider.provider_type.value,
                    base_url=primary_provider.base_url,
                    custom_headers=primary_provider.custom_headers or {},
                    supports_streaming=primary_model.supports_streaming,
                    supports_tools=primary_model.supports_tools,
                    supports_vision=primary_model.supports_vision,
                    supports_json_mode=primary_model.supports_json_mode,
                    is_fallback=False,
                )

            # Primary candidate is unhealthy or degraded: evaluate fallback chain
            fallback_reason = (
                f"Primary provider '{primary_provider.name if primary_provider else 'unknown'}' is "
                f"{primary_provider.status.value if primary_provider else 'unavailable'}"
            )

            for fallback_id in policy.fallback_model_ids:
                fb_model = await self.model_repo.get_by_id_and_project(fallback_id, project.id)
                if not fb_model or not fb_model.is_enabled:
                    continue
                fb_provider = await self.provider_repo.get_by_id_and_project(fb_model.provider_id, project.id)
                if not fb_provider or fb_provider.status in (ProviderStatus.ERROR, ProviderStatus.DISABLED):
                    continue

                # Viable fallback candidate found!
                await self.audit_repo.log_event(
                    project_id=project.id,
                    actor_id=actor_id or "system",
                    action=ProjectAuditAction.ROUTING_FALLBACK,
                    payload={
                        "policy_id": str(policy.id),
                        "primary_model_id": str(policy.primary_model_id),
                        "fallback_model_id": str(fb_model.id),
                        "reason": fallback_reason,
                    },
                )

                return ModelResolutionResponse(
                    model_id=str(fb_model.id),
                    upstream_model_id=fb_model.model_id,
                    display_name=fb_model.display_name,
                    provider_id=str(fb_provider.id),
                    provider_type=fb_provider.provider_type.value,
                    base_url=fb_provider.base_url,
                    custom_headers=fb_provider.custom_headers or {},
                    supports_streaming=fb_model.supports_streaming,
                    supports_tools=fb_model.supports_tools,
                    supports_vision=fb_model.supports_vision,
                    supports_json_mode=fb_model.supports_json_mode,
                    is_fallback=True,
                    fallback_reason=fallback_reason,
                )

            # If all fallback candidates are exhausted, return primary if it exists
            if primary_model and primary_provider:
                return ModelResolutionResponse(
                    model_id=str(primary_model.id),
                    upstream_model_id=primary_model.model_id,
                    display_name=primary_model.display_name,
                    provider_id=str(primary_provider.id),
                    provider_type=primary_provider.provider_type.value,
                    base_url=primary_provider.base_url,
                    custom_headers=primary_provider.custom_headers or {},
                    supports_streaming=primary_model.supports_streaming,
                    supports_tools=primary_model.supports_tools,
                    supports_vision=primary_model.supports_vision,
                    supports_json_mode=primary_model.supports_json_mode,
                    is_fallback=True,
                    fallback_reason=f"{fallback_reason} (no healthy fallback candidates available)",
                )

        # 2. Look up model directly by ID, upstream model_id, or display_name
        model = None
        try:
            model = await self.model_repo.get_by_id_and_project(request.model_identifier, project.id)
        except Exception:
            model = None

        if not model:
            # Query by search
            matched_models, _ = await self.model_repo.list_by_project(
                project_id=project.id,
                search=request.model_identifier,
                limit=1,
            )
            if matched_models:
                model = matched_models[0]

        if not model:
            raise NotFoundError(f"Model or routing policy '{request.model_identifier}' not found in project")

        provider = await self.provider_repo.get_by_id_and_project(model.provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider for model '{model.id}' not found in project")

        return ModelResolutionResponse(
            model_id=str(model.id),
            upstream_model_id=model.model_id,
            display_name=model.display_name,
            provider_id=str(provider.id),
            provider_type=provider.provider_type.value,
            base_url=provider.base_url,
            custom_headers=provider.custom_headers or {},
            supports_streaming=model.supports_streaming,
            supports_tools=model.supports_tools,
            supports_vision=model.supports_vision,
            supports_json_mode=model.supports_json_mode,
            is_fallback=False,
        )


def get_model_routing_service(
    routing_policy_repo: ProjectRoutingPolicyRepository = Depends(get_project_routing_policy_repository),
    model_repo: ProjectModelRepository = Depends(get_project_model_repository),
    provider_repo: ProjectProviderRepository = Depends(get_project_provider_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
) -> ModelRoutingService:
    """Dependency injection provider for ModelRoutingService."""
    return ModelRoutingService(
        routing_policy_repo=routing_policy_repo,
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
    )
