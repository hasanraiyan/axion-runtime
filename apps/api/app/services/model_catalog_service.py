"""
Model Catalog Service implementing dynamic discovery, capability inspection,
manual registration, and OCC-guarded updates for ProjectModel documents (SRS-06).
"""
from datetime import datetime, timezone
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
)
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectStatus,
)
from app.models.project_model import ModelType, ProjectModel
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
from app.schemas.model_catalog import (
    ModelCreateRequest,
    ModelResponse,
    ModelUpdateRequest,
)
from app.schemas.provider import (
    ProviderDiscoverySummaryResponse,
)
from app.services.provider_service import (
    ProviderManagementService,
    get_provider_service,
)


class ModelCatalogService:
    """
    Domain service orchestrating model registration, capability search,
    automated upstream discovery, and lifecycle management.
    """

    def __init__(
        self,
        model_repo: Optional[IProjectModelRepository] = None,
        provider_repo: Optional[IProjectProviderRepository] = None,
        project_repo: Optional[IProjectRepository] = None,
        audit_repo: Optional[IProjectAuditRepository] = None,
        provider_service: Optional[ProviderManagementService] = None,
    ) -> None:
        self.model_repo = model_repo if model_repo is not None else get_project_model_repository()
        self.provider_repo = provider_repo if provider_repo is not None else get_project_provider_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.provider_service = provider_service if provider_service is not None else get_provider_service()

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

    async def create_model(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: ModelCreateRequest,
        actor_id: str,
    ) -> ModelResponse:
        """
        Manually register a model under an existing active provider (FR-05).
        Enforces unique model_id per provider and OCC revision counter.
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        provider = await self.provider_repo.get_by_id_and_project(request.provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Parent provider '{request.provider_id}' not found in project")

        existing = await self.model_repo.get_by_provider_and_model_id(
            provider_id=provider.id,
            model_id=request.model_id,
            include_deleted=False,
        )
        if existing:
            raise ConflictError(
                f"Model with identifier '{request.model_id}' already exists for this provider"
            )

        if request.is_default:
            await self.model_repo.unset_other_defaults(project.id, request.model_type)

        now = datetime.now(timezone.utc)
        model_doc = ProjectModel(
            project_id=project.id,
            provider_id=provider.id,
            model_id=request.model_id,
            display_name=request.display_name,
            description=request.description,
            model_type=request.model_type,
            supports_streaming=request.supports_streaming,
            supports_tools=request.supports_tools,
            supports_vision=request.supports_vision,
            supports_json_mode=request.supports_json_mode,
            supports_reasoning=request.supports_reasoning,
            max_input_tokens=request.max_input_tokens,
            max_output_tokens=request.max_output_tokens,
            default_temperature=request.default_temperature,
            input_cost_per_million=request.input_cost_per_million,
            output_cost_per_million=request.output_cost_per_million,
            is_enabled=request.is_enabled,
            is_default=request.is_default,
            revision=1,
            created_at=now,
            updated_at=now,
        )

        created = await self.model_repo.create(model_doc)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MODEL_CREATED,
            payload={
                "model_id": str(created.id),
                "upstream_model_id": created.model_id,
                "provider_id": str(provider.id),
                "display_name": created.display_name,
            },
        )

        return ModelResponse.from_model(created, provider_name=provider.name)

    async def get_model(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        model_id: Union[str, PydanticObjectId, ObjectId],
    ) -> ModelResponse:
        """Inspect single model definition and capability flags (FR-06)."""
        project = await self._get_active_project(project_id, allow_archived=True)
        model = await self.model_repo.get_by_id_and_project(model_id, project.id)
        if not model:
            raise NotFoundError(f"Model '{model_id}' not found")

        provider = await self.provider_repo.get_by_id_and_project(model.provider_id, project.id, include_deleted=True)
        provider_name = provider.name if provider else None

        return ModelResponse.from_model(model, provider_name=provider_name)

    async def list_models(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Optional[Union[str, PydanticObjectId, ObjectId]] = None,
        model_type: Optional[ModelType] = None,
        supports_tools: Optional[bool] = None,
        supports_vision: Optional[bool] = None,
        supports_json_mode: Optional[bool] = None,
        is_enabled: Optional[bool] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ModelResponse], int]:
        """
        List models filtered by capability flags, provider, or modality (FR-06).
        Used by agent planners and human administrators.
        """
        project = await self._get_active_project(project_id, allow_archived=True)
        models, total = await self.model_repo.list_by_project(
            project_id=project.id,
            provider_id=provider_id,
            model_type=model_type,
            supports_tools=supports_tools,
            supports_vision=supports_vision,
            supports_json_mode=supports_json_mode,
            is_enabled=is_enabled,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit,
            include_deleted=False,
        )

        # Batch resolve provider names
        provider_ids = list({m.provider_id for m in models})
        prov_map: Dict[str, str] = {}
        for pid in provider_ids:
            p = await self.provider_repo.get_by_id_and_project(pid, project.id, include_deleted=True)
            if p:
                prov_map[str(pid)] = p.name

        responses = [
            ModelResponse.from_model(m, provider_name=prov_map.get(str(m.provider_id)))
            for m in models
        ]
        return responses, total

    async def update_model(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        model_id: Union[str, PydanticObjectId, ObjectId],
        request: ModelUpdateRequest,
        actor_id: str,
    ) -> ModelResponse:
        """Atomically update model capabilities or limits enforcing OCC revision (FR-08)."""
        project = await self._get_active_project(project_id, allow_archived=False)
        existing = await self.model_repo.get_by_id_and_project(model_id, project.id)
        if not existing:
            raise NotFoundError(f"Model '{model_id}' not found")

        update_dict: Dict[str, Any] = {}
        if request.display_name is not None:
            update_dict["display_name"] = request.display_name
        if request.description is not None:
            update_dict["description"] = request.description
        if request.model_type is not None:
            update_dict["model_type"] = request.model_type
        if request.supports_streaming is not None:
            update_dict["supports_streaming"] = request.supports_streaming
        if request.supports_tools is not None:
            update_dict["supports_tools"] = request.supports_tools
        if request.supports_vision is not None:
            update_dict["supports_vision"] = request.supports_vision
        if request.supports_json_mode is not None:
            update_dict["supports_json_mode"] = request.supports_json_mode
        if request.supports_reasoning is not None:
            update_dict["supports_reasoning"] = request.supports_reasoning
        if request.max_input_tokens is not None:
            update_dict["max_input_tokens"] = request.max_input_tokens
        if request.max_output_tokens is not None:
            update_dict["max_output_tokens"] = request.max_output_tokens
        if request.default_temperature is not None:
            update_dict["default_temperature"] = request.default_temperature
        if request.input_cost_per_million is not None:
            update_dict["input_cost_per_million"] = request.input_cost_per_million
        if request.output_cost_per_million is not None:
            update_dict["output_cost_per_million"] = request.output_cost_per_million
        if request.is_enabled is not None:
            update_dict["is_enabled"] = request.is_enabled
        if request.is_default is not None:
            update_dict["is_default"] = request.is_default
            if request.is_default:
                target_type = request.model_type or existing.model_type
                await self.model_repo.unset_other_defaults(project.id, target_type, exclude_id=existing.id)

        updated = await self.model_repo.update_with_revision(
            model_id=existing.id,
            project_id=project.id,
            expected_revision=request.revision,
            update_dict=update_dict,
        )

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MODEL_UPDATED,
            payload={
                "model_id": str(updated.id),
                "upstream_model_id": updated.model_id,
                "revision": updated.revision,
            },
        )

        provider = await self.provider_repo.get_by_id_and_project(updated.provider_id, project.id, include_deleted=True)
        provider_name = provider.name if provider else None

        return ModelResponse.from_model(updated, provider_name=provider_name)

    async def delete_model(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        model_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> bool:
        """Soft-delete a model from catalog (FR-08)."""
        project = await self._get_active_project(project_id, allow_archived=False)
        model = await self.model_repo.get_by_id_and_project(model_id, project.id)
        if not model:
            raise NotFoundError(f"Model '{model_id}' not found")

        success = await self.model_repo.soft_delete(model.id, project.id)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MODEL_DELETED,
            payload={
                "model_id": str(model.id),
                "upstream_model_id": model.model_id,
            },
        )

        return success

    async def discover_models(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> ProviderDiscoverySummaryResponse:
        """
        Query upstream provider API and auto-persist discovered models into database (FR-04).
        Updates existing models if capabilities have changed, or creates new records.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        provider = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        # Resolve live model catalog via provider service
        inspect_res = await self.provider_service.live_provider_models(project.id, provider.id)
        discovered_models = inspect_res.models

        created_count = 0
        updated_count = 0
        now = datetime.now(timezone.utc)

        for d_model in discovered_models:
            existing = await self.model_repo.get_by_provider_and_model_id(
                provider_id=provider.id,
                model_id=d_model.model_id,
                include_deleted=False,
            )

            if existing:
                # Re-discovery refreshes everything the upstream actually states.
                # Only values upstream is silent about are left untouched, so a
                # limit that upstream later corrects can no longer stay stale.
                update_dict: Dict[str, Any] = {}
                if d_model.model_type is not None and d_model.model_type != existing.model_type:
                    update_dict["model_type"] = d_model.model_type
                if d_model.supports_streaming is not None:
                    update_dict["supports_streaming"] = d_model.supports_streaming
                if d_model.supports_tools is not None:
                    update_dict["supports_tools"] = d_model.supports_tools
                if d_model.supports_vision is not None:
                    update_dict["supports_vision"] = d_model.supports_vision
                if d_model.supports_json_mode is not None:
                    update_dict["supports_json_mode"] = d_model.supports_json_mode
                if d_model.supports_reasoning is not None:
                    update_dict["supports_reasoning"] = d_model.supports_reasoning
                if d_model.max_input_tokens is not None:
                    update_dict["max_input_tokens"] = d_model.max_input_tokens
                if d_model.max_output_tokens is not None:
                    update_dict["max_output_tokens"] = d_model.max_output_tokens
                if d_model.default_temperature is not None:
                    update_dict["default_temperature"] = d_model.default_temperature
                if d_model.description is not None and not existing.description:
                    # Descriptions double as admin notes; only fill what is empty.
                    update_dict["description"] = d_model.description

                if update_dict:
                    await self.model_repo.update_with_revision(
                        model_id=existing.id,
                        project_id=project.id,
                        expected_revision=existing.revision,
                        update_dict=update_dict,
                    )
                updated_count += 1
            else:
                # Register new model. Unknown capabilities stay None (no invented
                # defaults); `model_type` is the only storage-required classification.
                new_doc = ProjectModel(
                    project_id=project.id,
                    provider_id=provider.id,
                    model_id=d_model.model_id,
                    display_name=d_model.display_name,
                    description=d_model.description,
                    model_type=d_model.model_type or ModelType.CHAT_COMPLETION,
                    supports_streaming=d_model.supports_streaming,
                    supports_tools=d_model.supports_tools,
                    supports_vision=d_model.supports_vision,
                    supports_json_mode=d_model.supports_json_mode,
                    supports_reasoning=d_model.supports_reasoning,
                    max_input_tokens=d_model.max_input_tokens,
                    max_output_tokens=d_model.max_output_tokens,
                    default_temperature=d_model.default_temperature,
                    is_enabled=True,
                    is_default=False,
                    revision=1,
                    created_at=now,
                    updated_at=now,
                )
                await self.model_repo.create(new_doc)
                created_count += 1

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.MODEL_CREATED,
            payload={
                "provider_id": str(provider.id),
                "discovered_count": len(discovered_models),
                "created_count": created_count,
                "updated_count": updated_count,
            },
        )

        return ProviderDiscoverySummaryResponse(
            provider_id=str(provider.id),
            discovered_count=len(discovered_models),
            created_count=created_count,
            updated_count=updated_count,
            models=discovered_models,
        )


def get_model_catalog_service(
    model_repo: ProjectModelRepository = Depends(get_project_model_repository),
    provider_repo: ProjectProviderRepository = Depends(get_project_provider_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    provider_service: ProviderManagementService = Depends(get_provider_service),
) -> ModelCatalogService:
    """Dependency injection provider for ModelCatalogService."""
    return ModelCatalogService(
        model_repo=model_repo,
        provider_repo=provider_repo,
        project_repo=project_repo,
        audit_repo=audit_repo,
        provider_service=provider_service,
    )
