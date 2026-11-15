from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.project_routing_policy import ProjectRoutingPolicy


class RoutingPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Friendly routing policy name")
    description: Optional[str] = Field(default=None, max_length=500)
    primary_model_id: str = Field(..., description="Target ProjectModel ID representing primary candidate")
    fallback_model_ids: List[str] = Field(
        default_factory=list, max_length=5, description="Ordered backup model IDs (max 5)"
    )
    retry_timeout_ms: int = Field(default=3000, ge=100, description="Latency threshold before fallback")
    fallback_on_codes: List[int] = Field(
        default_factory=lambda: [429, 500, 502, 503], description="HTTP status codes triggering fallback switch"
    )
    is_active: bool = Field(default=True, description="Active toggle for this policy")


class RoutingPolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    primary_model_id: Optional[str] = None
    fallback_model_ids: Optional[List[str]] = None
    retry_timeout_ms: Optional[int] = Field(default=None, ge=100)
    fallback_on_codes: Optional[List[int]] = None
    is_active: Optional[bool] = None
    revision: int = Field(..., description="Current OCC revision counter for optimistic locking")


class RoutingPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    name: str
    description: Optional[str] = None
    primary_model_id: str
    fallback_model_ids: List[str] = Field(default_factory=list)
    retry_timeout_ms: int
    fallback_on_codes: List[int]
    is_active: bool
    revision: int
    created_at: datetime
    updated_at: datetime

    @field_validator("id", "project_id", "primary_model_id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v

    @field_validator("fallback_model_ids", mode="before")
    @classmethod
    def convert_ids(cls, v: Any) -> Any:
        if isinstance(v, list):
            return [str(item) for item in v]
        return v

    @classmethod
    def from_model(cls, policy: ProjectRoutingPolicy) -> "RoutingPolicyResponse":
        return cls(
            id=str(policy.id),
            project_id=str(policy.project_id),
            name=policy.name,
            description=policy.description,
            primary_model_id=str(policy.primary_model_id),
            fallback_model_ids=[str(mid) for mid in policy.fallback_model_ids],
            retry_timeout_ms=policy.retry_timeout_ms,
            fallback_on_codes=policy.fallback_on_codes,
            is_active=policy.is_active,
            revision=policy.revision,
            created_at=policy.created_at,
            updated_at=policy.updated_at,
        )


class ModelResolutionRequest(BaseModel):
    model_identifier: str = Field(..., description="Target model ID, display name, or routing policy name/ID")


class ModelResolutionResponse(BaseModel):
    model_id: str
    upstream_model_id: str
    display_name: str
    provider_id: str
    provider_type: str
    base_url: Optional[str] = None
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    supports_streaming: bool = True
    supports_tools: bool = False
    supports_vision: bool = False
    supports_json_mode: bool = False
    is_fallback: bool = False
    fallback_reason: Optional[str] = None
