from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.project_model import ModelType, ProjectModel


class ModelCreateRequest(BaseModel):
    provider_id: str = Field(..., description="Parent provider document ID")
    model_id: str = Field(..., min_length=1, max_length=150, description="Upstream model identifier")
    display_name: str = Field(..., min_length=1, max_length=100, description="Human-friendly model name")
    description: Optional[str] = Field(default=None, max_length=500, description="Notes on model specialization")
    model_type: ModelType = Field(default=ModelType.CHAT_COMPLETION, description="Model type / modality")
    supports_streaming: Optional[bool] = Field(default=None, description="SSE streaming support (omit when unknown)")
    supports_tools: Optional[bool] = Field(default=None, description="Function/tool calling support (omit when unknown)")
    supports_vision: Optional[bool] = Field(default=None, description="Multimodal vision input support (omit when unknown)")
    supports_json_mode: Optional[bool] = Field(default=None, description="Structured JSON output support (omit when unknown)")
    supports_reasoning: Optional[bool] = Field(default=None, description="Extended reasoning / CoT support (omit when unknown)")
    max_input_tokens: Optional[int] = Field(default=None, gt=0, description="Context window token limit")
    max_output_tokens: Optional[int] = Field(default=None, gt=0, description="Maximum generation token limit")
    default_temperature: Optional[float] = Field(
        default=None, ge=0.0, le=2.0, description="Default generation temperature (omit when unknown)"
    )
    input_cost_per_million: Optional[float] = Field(default=None, ge=0.0, description="USD cost per 1M prompt tokens")
    output_cost_per_million: Optional[float] = Field(default=None, ge=0.0, description="USD cost per 1M completion tokens")
    is_enabled: bool = Field(default=True, description="Toggle whether model is selectable by agents")
    is_default: bool = Field(default=False, description="Default model for this model type")


class ModelUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    model_type: Optional[ModelType] = None
    supports_streaming: Optional[bool] = None
    supports_tools: Optional[bool] = None
    supports_vision: Optional[bool] = None
    supports_json_mode: Optional[bool] = None
    supports_reasoning: Optional[bool] = None
    max_input_tokens: Optional[int] = Field(default=None, gt=0)
    max_output_tokens: Optional[int] = Field(default=None, gt=0)
    default_temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    input_cost_per_million: Optional[float] = Field(default=None, ge=0.0)
    output_cost_per_million: Optional[float] = Field(default=None, ge=0.0)
    is_enabled: Optional[bool] = None
    is_default: Optional[bool] = None
    revision: int = Field(..., description="Current OCC revision counter for optimistic locking")


class ModelResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    provider_id: str
    model_id: str
    display_name: str
    description: Optional[str] = None
    model_type: ModelType
    supports_streaming: Optional[bool] = None
    supports_tools: Optional[bool] = None
    supports_vision: Optional[bool] = None
    supports_json_mode: Optional[bool] = None
    supports_reasoning: Optional[bool] = None
    max_input_tokens: Optional[int] = None
    max_output_tokens: Optional[int] = None
    default_temperature: Optional[float] = None
    input_cost_per_million: Optional[float] = None
    output_cost_per_million: Optional[float] = None
    is_enabled: bool
    is_default: bool
    revision: int
    created_at: datetime
    updated_at: datetime
    provider_name: Optional[str] = None

    @field_validator("id", "project_id", "provider_id", mode="before")
    @classmethod
    def convert_id(cls, v: Any) -> Any:
        return str(v) if v is not None else v

    @classmethod
    def from_model(cls, model: ProjectModel, provider_name: Optional[str] = None) -> "ModelResponse":
        return cls(
            id=str(model.id),
            project_id=str(model.project_id),
            provider_id=str(model.provider_id),
            model_id=model.model_id,
            display_name=model.display_name,
            description=model.description,
            model_type=model.model_type,
            supports_streaming=model.supports_streaming,
            supports_tools=model.supports_tools,
            supports_vision=model.supports_vision,
            supports_json_mode=model.supports_json_mode,
            supports_reasoning=model.supports_reasoning,
            max_input_tokens=model.max_input_tokens,
            max_output_tokens=model.max_output_tokens,
            default_temperature=model.default_temperature,
            input_cost_per_million=model.input_cost_per_million,
            output_cost_per_million=model.output_cost_per_million,
            is_enabled=model.is_enabled,
            is_default=model.is_default,
            revision=model.revision,
            created_at=model.created_at,
            updated_at=model.updated_at,
            provider_name=provider_name,
        )


class ModelFilterParams(BaseModel):
    provider_id: Optional[str] = None
    model_type: Optional[ModelType] = None
    supports_tools: Optional[bool] = None
    supports_vision: Optional[bool] = None
    supports_json_mode: Optional[bool] = None
    is_enabled: Optional[bool] = None
    search: Optional[str] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
