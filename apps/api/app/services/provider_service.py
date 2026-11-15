"""
Provider Service implementing core domain business rules, zero-plaintext credential binding,
upstream healthchecks, dynamic model discovery, and OCC-guarded lifecycle management (SRS-06).
"""
from datetime import datetime, timezone
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from beanie import PydanticObjectId
from bson import ObjectId
from fastapi import Depends
import httpx

from app.core.crypto import CryptoService, get_crypto_service
from app.core.exceptions import (
    BadRequestError,
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
    ISecretRepository,
)
from app.models.project import (
    Project,
    ProjectAuditAction,
    ProjectStatus,
)
from app.models.project_model import ModelType
from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
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
from app.repositories.secret_repository import (
    ProjectSecretRepository,
    get_secret_repository,
)
from app.schemas.provider import (
    DiscoveredModelInfo,
    ProviderCreateRequest,
    ProviderHealthcheckResponse,
    ProviderInspectRequest,
    ProviderInspectResponse,
    ProviderResponse,
    ProviderUpdateRequest,
)


def infer_model_capabilities(model_id: str, display_name: Optional[str] = None) -> DiscoveredModelInfo:
    """Infer model capabilities, modality, and default limits from upstream identifier."""
    mid = model_id.lower()
    dname = display_name or model_id

    is_embedding = "embed" in mid
    is_reranker = "rerank" in mid

    if is_embedding:
        model_type = ModelType.EMBEDDING
    elif is_reranker:
        model_type = ModelType.RERANKER
    else:
        model_type = ModelType.CHAT_COMPLETION

    is_chat = model_type == ModelType.CHAT_COMPLETION

    supports_vision = is_chat and any(
        v in mid for v in ["vision", "omni", "gpt-4o", "gemini", "claude-3", "vl", "pixtral"]
    )
    supports_tools = is_chat and any(
        t in mid for t in ["gpt", "claude", "gemini", "mistral", "deepseek", "qwen", "llama", "command"]
    )
    supports_json_mode = supports_tools
    supports_reasoning = is_chat and any(
        r in mid for r in ["o1", "o3", "r1", "reason", "thinking", "deepseek-r1"]
    )

    max_input = 128000
    max_output: Optional[int] = 4096
    if "gemini" in mid:
        max_input = 1000000
        max_output = 8192
    elif "claude-3" in mid:
        max_input = 200000
        max_output = 8192
    elif is_embedding or is_reranker:
        max_input = 8192
        max_output = None

    return DiscoveredModelInfo(
        model_id=model_id,
        display_name=dname,
        model_type=model_type,
        supports_streaming=is_chat,
        supports_tools=supports_tools,
        supports_vision=supports_vision,
        supports_json_mode=supports_json_mode,
        supports_reasoning=supports_reasoning,
        max_input_tokens=max_input,
        max_output_tokens=max_output,
        default_temperature=0.7 if is_chat else 0.0,
    )


class ProviderManagementService:
    """
    Domain service orchestrating provider connections, secret binding,
    zero-plaintext security, live healthchecks, and model inspection.
    """

    def __init__(
        self,
        provider_repo: Optional[IProjectProviderRepository] = None,
        model_repo: Optional[IProjectModelRepository] = None,
        project_repo: Optional[IProjectRepository] = None,
        secret_repo: Optional[ISecretRepository] = None,
        audit_repo: Optional[IProjectAuditRepository] = None,
        crypto_service: Optional[CryptoService] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.provider_repo = provider_repo if provider_repo is not None else get_project_provider_repository()
        self.model_repo = model_repo if model_repo is not None else get_project_model_repository()
        self.project_repo = project_repo if project_repo is not None else get_project_repository()
        self.secret_repo = secret_repo if secret_repo is not None else get_secret_repository()
        self.audit_repo = audit_repo if audit_repo is not None else get_project_audit_repository()
        self.crypto_service = crypto_service if crypto_service is not None else get_crypto_service()
        self.http_client = http_client

    async def _get_active_project(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        allow_archived: bool = False,
    ) -> Project:
        """Enforce project boundary and lifecycle state."""
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

    def _generate_slug(self, name: str) -> str:
        """Generate a URL-safe lowercase slug from name."""
        cleaned = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
        cleaned = re.sub(r"-+", "-", cleaned)
        return cleaned if len(cleaned) >= 1 else "provider"

    async def _resolve_secret_plaintext(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        secret_id: Union[str, PydanticObjectId, ObjectId],
    ) -> Tuple[str, str]:
        """
        In-memory decryption of a project secret (FR-11 Zero Plaintext Invariant).
        Returns tuple of (secret_name, decrypted_plaintext).
        """
        secret = await self.secret_repo.get_by_id_and_project(secret_id, project_id)
        if not secret:
            raise NotFoundError(f"Secret '{secret_id}' not found in project")
        if secret.is_deleted:
            raise BadRequestError(f"Referenced secret '{secret_id}' has been deleted")

        plaintext = await self.crypto_service.decrypt_secret(
            secret.envelope,
            str(project_id),
            secret.environment,
            secret.name,
        )
        return secret.name, plaintext

    async def _execute_upstream_probe(
        self,
        provider_type: ProviderType,
        api_key: str,
        base_url: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 15,
    ) -> Tuple[HealthcheckStatus, Optional[int], Optional[str]]:
        """
        Execute live HTTP ping probe to verify credentials and endpoint availability (FR-03).
        Returns (healthcheck_status, latency_ms, message).
        """
        start_time = time.monotonic()
        headers = dict(custom_headers or {})

        url = ""
        if provider_type in (ProviderType.OPENAI, ProviderType.CUSTOM_OPENAI_COMPATIBLE):
            base = (base_url or "https://api.openai.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")
        elif provider_type == ProviderType.GOOGLE_GENAI:
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            headers.setdefault("Content-Type", "application/json")
        elif provider_type == ProviderType.ANTHROPIC:
            base = (base_url or "https://api.anthropic.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("x-api-key", api_key)
            headers.setdefault("anthropic-version", "2023-06-01")
        elif provider_type == ProviderType.MISTRAL:
            base = (base_url or "https://api.mistral.ai/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")
        elif provider_type == ProviderType.COHERE:
            base = (base_url or "https://api.cohere.ai/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")
        else:
            base = (base_url or "https://api.openai.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")

        try:
            if self.http_client:
                resp = await self.http_client.get(url, headers=headers, timeout=timeout_seconds)
            else:
                async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                    resp = await client.get(url, headers=headers)

            latency_ms = max(1, int((time.monotonic() - start_time) * 1000))

            if resp.status_code == 200 or resp.is_success:
                return HealthcheckStatus.HEALTHY, latency_ms, "Provider connection verified successfully"
            elif resp.status_code in (401, 403):
                return HealthcheckStatus.AUTH_FAILED, latency_ms, f"Authentication failed: HTTP {resp.status_code}"
            elif resp.status_code == 429:
                return HealthcheckStatus.RATE_LIMITED, latency_ms, "Upstream rate limit exceeded (HTTP 429)"
            else:
                return HealthcheckStatus.UNREACHABLE, latency_ms, f"Upstream error: HTTP {resp.status_code}"

        except httpx.TimeoutException:
            return HealthcheckStatus.UNREACHABLE, None, "Connection timed out"
        except Exception as exc:
            return HealthcheckStatus.UNREACHABLE, None, f"Connection failed: {str(exc)}"

    async def create_provider(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: ProviderCreateRequest,
        actor_id: str,
    ) -> ProviderResponse:
        """
        Register a new provider connection bound to a project secret (FR-01, FR-02).
        Executes immediate live connectivity test (FR-03) and initializes OCC revision.
        """
        project = await self._get_active_project(project_id, allow_archived=False)

        # Verify secret existence and tenant boundary
        secret_name, plaintext_key = await self._resolve_secret_plaintext(project.id, request.secret_id)

        slug = request.slug or self._generate_slug(request.name)

        # Check slug uniqueness within project
        existing_slug = await self.provider_repo.get_by_slug(project.id, slug)
        if existing_slug:
            raise ConflictError(f"Provider with slug '{slug}' already exists in this project")

        existing_name = await self.provider_repo.get_by_name(project.id, request.name)
        if existing_name:
            raise ConflictError(f"Provider with name '{request.name}' already exists in this project")

        # Unset previous default if requested
        if request.is_default:
            await self.provider_repo.unset_other_defaults(project.id)

        # Immediate connectivity test (FR-01 step 5 & FR-03)
        h_status, latency, message = await self._execute_upstream_probe(
            provider_type=request.provider_type,
            api_key=plaintext_key,
            base_url=request.base_url,
            custom_headers=request.custom_headers,
            timeout_seconds=min(request.timeout_seconds, 15),
        )

        now = datetime.now(timezone.utc)
        provider_status = ProviderStatus.ACTIVE if h_status == HealthcheckStatus.HEALTHY else (
            ProviderStatus.DEGRADED if h_status == HealthcheckStatus.RATE_LIMITED else ProviderStatus.ERROR
        )

        provider_doc = ProjectProvider(
            project_id=project.id,
            name=request.name,
            slug=slug,
            provider_type=request.provider_type,
            secret_id=PydanticObjectId(request.secret_id),
            base_url=request.base_url,
            api_version=request.api_version,
            custom_headers=request.custom_headers,
            timeout_seconds=request.timeout_seconds,
            max_retries=request.max_retries,
            status=provider_status,
            last_healthcheck_at=now,
            healthcheck_status=h_status,
            healthcheck_latency_ms=latency,
            healthcheck_message=message,
            is_default=request.is_default,
            revision=1,
            created_by=actor_id,
            updated_by=actor_id,
            created_at=now,
            updated_at=now,
        )

        created = await self.provider_repo.create(provider_doc)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.PROVIDER_CREATED,
            payload={
                "provider_id": str(created.id),
                "name": created.name,
                "slug": created.slug,
                "provider_type": created.provider_type.value,
                "status": created.status.value,
                "healthcheck_status": h_status.value,
            },
        )

        return ProviderResponse.from_model(created, secret_name=secret_name)

    async def get_provider(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
    ) -> ProviderResponse:
        """Fetch provider metadata ensuring project tenant boundary."""
        project = await self._get_active_project(project_id, allow_archived=True)
        provider = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        secret_name: Optional[str] = None
        secret = await self.secret_repo.get_by_id_and_project(provider.secret_id, project.id, include_deleted=True)
        if secret:
            secret_name = secret.name

        return ProviderResponse.from_model(provider, secret_name=secret_name)

    async def list_providers(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_type: Optional[ProviderType] = None,
        status: Optional[ProviderStatus] = None,
        search: Optional[str] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[ProviderResponse], int]:
        """List active providers scoped to project with filtering and pagination."""
        project = await self._get_active_project(project_id, allow_archived=True)
        providers, total = await self.provider_repo.list_by_project(
            project_id=project.id,
            provider_type=provider_type,
            status=status,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit,
            include_deleted=False,
        )

        # Batch resolve secret names for UI convenience (names only, ZERO plaintext)
        secret_ids = list({p.secret_id for p in providers})
        secret_map: Dict[str, str] = {}
        for sid in secret_ids:
            sec = await self.secret_repo.get_by_id_and_project(sid, project.id, include_deleted=True)
            if sec:
                secret_map[str(sid)] = sec.name

        responses = [
            ProviderResponse.from_model(p, secret_name=secret_map.get(str(p.secret_id)))
            for p in providers
        ]
        return responses, total

    async def update_provider(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
        request: ProviderUpdateRequest,
        actor_id: str,
    ) -> ProviderResponse:
        """Atomically update provider settings enforcing OCC revision counter (FR-08)."""
        project = await self._get_active_project(project_id, allow_archived=False)
        existing = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not existing:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        update_dict: Dict[str, Any] = {"updated_by": actor_id}
        if request.name is not None:
            update_dict["name"] = request.name
        if request.slug is not None:
            update_dict["slug"] = request.slug
        if request.secret_id is not None:
            # Verify new secret tenant binding
            await self._resolve_secret_plaintext(project.id, request.secret_id)
            update_dict["secret_id"] = PydanticObjectId(request.secret_id)
        if request.base_url is not None:
            update_dict["base_url"] = request.base_url
        if request.api_version is not None:
            update_dict["api_version"] = request.api_version
        if request.custom_headers is not None:
            update_dict["custom_headers"] = request.custom_headers
        if request.timeout_seconds is not None:
            update_dict["timeout_seconds"] = request.timeout_seconds
        if request.max_retries is not None:
            update_dict["max_retries"] = request.max_retries
        if request.status is not None:
            update_dict["status"] = request.status
        if request.is_default is not None:
            update_dict["is_default"] = request.is_default
            if request.is_default:
                await self.provider_repo.unset_other_defaults(project.id, exclude_id=existing.id)

        updated = await self.provider_repo.update_with_revision(
            provider_id=existing.id,
            project_id=project.id,
            expected_revision=request.revision,
            update_dict=update_dict,
        )

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.PROVIDER_UPDATED,
            payload={
                "provider_id": str(updated.id),
                "name": updated.name,
                "revision": updated.revision,
            },
        )

        secret_name, _ = await self._resolve_secret_plaintext(project.id, updated.secret_id)
        return ProviderResponse.from_model(updated, secret_name=secret_name)

    async def delete_provider(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> bool:
        """
        Soft-delete a provider and cascade soft-delete all child models (FR-08).
        Emits PROVIDER_DELETED audit event.
        """
        project = await self._get_active_project(project_id, allow_archived=False)
        provider = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        success = await self.provider_repo.soft_delete(provider.id, project.id)

        # Cascade soft-delete all models belonging to this provider
        await self.model_repo.soft_delete_by_provider(provider.id, project.id)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.PROVIDER_DELETED,
            payload={
                "provider_id": str(provider.id),
                "name": provider.name,
                "slug": provider.slug,
            },
        )

        return success

    async def test_provider_connection(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
        actor_id: str,
    ) -> ProviderHealthcheckResponse:
        """Execute on-demand live connectivity test for an existing provider (FR-03)."""
        project = await self._get_active_project(project_id, allow_archived=False)
        provider = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        _, plaintext_key = await self._resolve_secret_plaintext(project.id, provider.secret_id)

        h_status, latency, message = await self._execute_upstream_probe(
            provider_type=provider.provider_type,
            api_key=plaintext_key,
            base_url=provider.base_url,
            custom_headers=provider.custom_headers,
            timeout_seconds=min(provider.timeout_seconds, 15),
        )

        new_status = ProviderStatus.ACTIVE if h_status == HealthcheckStatus.HEALTHY else (
            ProviderStatus.DEGRADED if h_status == HealthcheckStatus.RATE_LIMITED else ProviderStatus.ERROR
        )

        updated = await self.provider_repo.update_healthcheck(
            provider_id=provider.id,
            project_id=project.id,
            healthcheck_status=h_status,
            latency_ms=latency,
            message=message,
            status=new_status,
        )

        checked_at = updated.last_healthcheck_at if updated and updated.last_healthcheck_at else datetime.now(timezone.utc)

        await self.audit_repo.log_event(
            project_id=project.id,
            actor_id=actor_id,
            action=ProjectAuditAction.PROVIDER_HEALTHCHECK,
            payload={
                "provider_id": str(provider.id),
                "healthcheck_status": h_status.value,
                "status": new_status.value,
                "latency_ms": latency,
            },
        )

        return ProviderHealthcheckResponse(
            provider_id=str(provider.id),
            status=new_status,
            healthcheck_status=h_status,
            latency_ms=latency,
            message=message,
            checked_at=checked_at,
        )

    async def _fetch_upstream_model_catalog(
        self,
        provider_type: ProviderType,
        api_key: str,
        base_url: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> List[DiscoveredModelInfo]:
        """Fetch and normalize model listings from upstream API without persisting."""
        headers = dict(custom_headers or {})

        url = ""
        if provider_type in (ProviderType.OPENAI, ProviderType.CUSTOM_OPENAI_COMPATIBLE):
            base = (base_url or "https://api.openai.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")
        elif provider_type == ProviderType.GOOGLE_GENAI:
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            headers.setdefault("Content-Type", "application/json")
        elif provider_type == ProviderType.ANTHROPIC:
            base = (base_url or "https://api.anthropic.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("x-api-key", api_key)
            headers.setdefault("anthropic-version", "2023-06-01")
        else:
            base = (base_url or "https://api.openai.com/v1").rstrip("/")
            url = f"{base}/models"
            headers.setdefault("Authorization", f"Bearer {api_key}")

        raw_models: List[Dict[str, Any]] = []
        try:
            if self.http_client:
                resp = await self.http_client.get(url, headers=headers, timeout=20)
            else:
                async with httpx.AsyncClient(timeout=20) as client:
                    resp = await client.get(url, headers=headers)

            if not resp.is_success:
                raise BadRequestError(f"Failed to query upstream model list: HTTP {resp.status_code}")

            data = resp.json()
            if isinstance(data, list):
                raw_models = data
            elif isinstance(data, dict):
                raw_models = data.get("data") or data.get("models") or []
        except BadRequestError:
            raise
        except Exception as exc:
            raise BadRequestError(f"Failed to reach upstream model list: {str(exc)}") from exc

        discovered: List[DiscoveredModelInfo] = []
        for item in raw_models:
            if not isinstance(item, dict):
                continue
            model_id = item.get("id") or item.get("name")
            if not model_id:
                continue
            # Google Gemini format clean: 'models/gemini-1.5-pro' -> 'gemini-1.5-pro'
            clean_id = model_id.removeprefix("models/") if isinstance(model_id, str) else str(model_id)
            display_name = item.get("displayName") or item.get("display_name") or clean_id
            discovered.append(infer_model_capabilities(clean_id, display_name))

        return discovered

    async def inspect_upstream_models(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        request: ProviderInspectRequest,
    ) -> ProviderInspectResponse:
        """
        Probe upstream provider in real-time using in-flight key or secret_id (FR-13 Mode 1).
        Zero plaintext credentials stored or logged.
        """
        project = await self._get_active_project(project_id, allow_archived=True)

        if request.secret_id:
            _, api_key = await self._resolve_secret_plaintext(project.id, request.secret_id)
        elif request.api_key:
            api_key = request.api_key.get_secret_value()
        else:
            raise BadRequestError("Either secret_id or api_key must be supplied")

        models = await self._fetch_upstream_model_catalog(
            provider_type=request.provider_type,
            api_key=api_key,
            base_url=request.base_url,
            custom_headers=request.custom_headers,
        )

        return ProviderInspectResponse(
            provider_type=request.provider_type,
            models=models,
            total_models=len(models),
        )

    async def live_provider_models(
        self,
        project_id: Union[str, PydanticObjectId, ObjectId],
        provider_id: Union[str, PydanticObjectId, ObjectId],
    ) -> ProviderInspectResponse:
        """Live query upstream using an existing provider's saved credentials (FR-13 Mode 2)."""
        project = await self._get_active_project(project_id, allow_archived=True)
        provider = await self.provider_repo.get_by_id_and_project(provider_id, project.id)
        if not provider:
            raise NotFoundError(f"Provider '{provider_id}' not found")

        _, api_key = await self._resolve_secret_plaintext(project.id, provider.secret_id)

        models = await self._fetch_upstream_model_catalog(
            provider_type=provider.provider_type,
            api_key=api_key,
            base_url=provider.base_url,
            custom_headers=provider.custom_headers,
        )

        return ProviderInspectResponse(
            provider_type=provider.provider_type,
            models=models,
            total_models=len(models),
        )


def get_provider_service(
    provider_repo: ProjectProviderRepository = Depends(get_project_provider_repository),
    model_repo: ProjectModelRepository = Depends(get_project_model_repository),
    project_repo: ProjectRepository = Depends(get_project_repository),
    secret_repo: ProjectSecretRepository = Depends(get_secret_repository),
    audit_repo: ProjectAuditRepository = Depends(get_project_audit_repository),
    crypto_service: CryptoService = Depends(get_crypto_service),
) -> ProviderManagementService:
    """Dependency injection provider for ProviderManagementService."""
    return ProviderManagementService(
        provider_repo=provider_repo,
        model_repo=model_repo,
        project_repo=project_repo,
        secret_repo=secret_repo,
        audit_repo=audit_repo,
        crypto_service=crypto_service,
    )
