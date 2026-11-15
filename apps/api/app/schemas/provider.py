from datetime import datetime
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.models.project_model import ModelType


class ProviderCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable provider name")
    slug: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        description="URL-safe unique slug within the project (auto-generated if omitted)",
    )
    provider_type: ProviderType = Field(..., description="Supported provider architecture")
    secret_id: str = Field(..., description="Foreign key to project_secrets (MOD-02)")
    base_url: Optional[str] = Field(
        default=None, description="Upstream API endpoint URL (mandatory for custom_openai_compatible)"
    )
    api_version: Optional[str] = Field(default=None, max_length=50, description="API version")
    custom_headers: Dict[str, str] = Field(
        default_factory=dict, description="Arbitrary key-value string pairs injected into HTTP calls"
    )
    timeout_seconds: int = Field(default=60, ge=1, le=600, description="Read and socket timeout in seconds")
    max_retries: int = Field(default=2, ge=0, le=5, description="Retry attempts on transient 5xx/network errors")
    is_default: bool = Field(default=False, description="Whether to designate as the default project provider")

    @field_validator("custom_headers")
    @classmethod
    def validate_no_crlf_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        for k, v in headers.items():
            if re.search(r"[\r\n]", k) or re.search(r"[\r\n]", str(v)):
                raise ValueError("CRLF injection detected in header keys or values")
        return headers

    @model_validator(mode="after")
    def validate_custom_provider_base_url(self) -> "ProviderCreateRequest":
        if self.provider_type == ProviderType.CUSTOM_OPENAI_COMPATIBLE:
            if not self.base_url:
                raise ValueError("base_url is required for custom_openai_compatible provider")
            if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
                raise ValueError("base_url must start with http:// or https://")
        return self


class ProviderUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    slug: Optional[str] = Field(
        default=None, min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
    )
    secret_id: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=600)
    max_retries: Optional[int] = Field(default=None, ge=0, le=5)
    status: Optional[ProviderStatus] = None
    is_default: Optional[bool] = None
    revision: int = Field(..., description="Current OCC revision counter for optimistic locking")

    @field_validator("custom_headers")
    @classmethod
    def validate_no_crlf_headers(cls, headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if headers is not None:
            for k, v in headers.items():
                if re.search(r"[\r\n]", k) or re.search(r"[\r\n]", str(v)):
                    raise ValueError("CRLF injection detected in header keys or values")
        return headers


class ProviderSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    name: str
    slug: str
    provider_type: ProviderType
    secret_id: str
    status: ProviderStatus
    is_default: bool
    last_healthcheck_at: Optional[datetime] = None
    healthcheck_status: Optional[HealthcheckStatus] = None
    healthcheck_latency_ms: Optional[int] = None
    revision: int
    created_at: datetime
    updated_at: datetime

    @field_validator("id", "project_id", "secret_id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class ProviderResponse(ProviderSummaryResponse):
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = 60
    max_retries: int = 2
    healthcheck_message: Optional[str] = None
    created_by: str
    updated_by: str
    secret_name: Optional[str] = Field(default=None, description="Masked/resolved secret name from MOD-02")

    @classmethod
    def from_model(
        cls, provider: ProjectProvider, secret_name: Optional[str] = None
    ) -> "ProviderResponse":
        return cls(
            id=str(provider.id),
            project_id=str(provider.project_id),
            name=provider.name,
            slug=provider.slug,
            provider_type=provider.provider_type,
            secret_id=str(provider.secret_id),
            status=provider.status,
            is_default=provider.is_default,
            last_healthcheck_at=provider.last_healthcheck_at,
            healthcheck_status=provider.healthcheck_status,
            healthcheck_latency_ms=provider.healthcheck_latency_ms,
            healthcheck_message=provider.healthcheck_message,
            base_url=provider.base_url,
            api_version=provider.api_version,
            custom_headers=provider.custom_headers or {},
            timeout_seconds=provider.timeout_seconds,
            max_retries=provider.max_retries,
            created_by=provider.created_by,
            updated_by=provider.updated_by,
            revision=provider.revision,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
            secret_name=secret_name,
        )


class ProviderHealthcheckResponse(BaseModel):
    provider_id: str
    status: ProviderStatus
    healthcheck_status: HealthcheckStatus
    latency_ms: Optional[int] = None
    message: Optional[str] = None
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveredModelInfo(BaseModel):
    model_id: str = Field(..., description="Upstream model identifier")
    display_name: str = Field(..., description="Human-friendly model name")
    description: Optional[str] = None
    owned_by: Optional[str] = Field(default=None, description="Owner organization or user returned by upstream")
    created_at_upstream: Optional[int] = Field(default=None, description="Unix timestamp of model creation upstream")
    model_type: Optional[ModelType] = Field(default=None, description="Model type if reported upstream")
    supports_streaming: Optional[bool] = Field(default=None, description="SSE streaming support if reported upstream")
    supports_tools: Optional[bool] = Field(default=None, description="Function/tool calling support if reported upstream")
    supports_vision: Optional[bool] = Field(default=None, description="Multimodal vision input if reported upstream")
    supports_json_mode: Optional[bool] = Field(default=None, description="Structured JSON output if reported upstream")
    supports_reasoning: Optional[bool] = Field(default=None, description="Extended reasoning if reported upstream")
    max_input_tokens: Optional[int] = Field(default=None, description="Upstream context limit if reported")
    max_output_tokens: Optional[int] = Field(default=None, description="Upstream output limit if reported")
    default_temperature: Optional[float] = Field(default=None, description="Recommended generation temperature if reported")


class ProviderInspectRequest(BaseModel):
    """Pre-registration or live inspection request (FR-13). Zero plaintext stored."""
    provider_type: ProviderType
    secret_id: Optional[str] = Field(default=None, description="Existing secret ID if saved")
    api_key: Optional[SecretStr] = Field(default=None, description="Transient in-flight API key for preview")
    base_url: Optional[str] = None
    custom_headers: Dict[str, str] = Field(default_factory=dict)

    @field_validator("custom_headers")
    @classmethod
    def validate_no_crlf_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        for k, v in headers.items():
            if re.search(r"[\r\n]", k) or re.search(r"[\r\n]", str(v)):
                raise ValueError("CRLF injection detected in header keys or values")
        return headers

    @model_validator(mode="after")
    def validate_key_or_secret(self) -> "ProviderInspectRequest":
        if not self.secret_id and not self.api_key:
            raise ValueError("Either secret_id or api_key must be provided for inspection")
        return self


class ProviderInspectResponse(BaseModel):
    provider_type: ProviderType
    models: List[DiscoveredModelInfo]
    total_models: int


class ProviderDiscoverySummaryResponse(BaseModel):
    provider_id: str
    discovered_count: int
    created_count: int
    updated_count: int
    models: List[DiscoveredModelInfo]
