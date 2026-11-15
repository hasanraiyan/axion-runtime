from datetime import datetime
from enum import Enum
from typing import Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class ModelType(str, Enum):
    """Model modality / capability classification (SRS-06 Section 4.2)."""

    CHAT_COMPLETION = "chat_completion"
    TEXT_COMPLETION = "text_completion"
    EMBEDDING = "embedding"
    RERANKER = "reranker"


class ProjectModel(BaseDocument):
    """
    Project Model document representing an upstream LLM model definition,
    its capability flags, context window limits, and cost metadata.
    """

    project_id: PydanticObjectId = Field(
        ..., description="Foreign key binding the model strictly to an Axion Project"
    )
    provider_id: PydanticObjectId = Field(
        ..., description="Foreign key binding the model to its parent ProjectProvider"
    )
    model_id: str = Field(
        ..., min_length=1, max_length=150, description="Upstream identifier (e.g., 'gemini-1.5-pro', 'gpt-4o')"
    )
    display_name: str = Field(
        ..., min_length=1, max_length=100, description="Human-friendly name displayed in UI / catalog"
    )
    description: Optional[str] = Field(
        default=None, max_length=500, description="Notes on model strengths, domain specialization, or architecture"
    )
    model_type: ModelType = Field(
        default=ModelType.CHAT_COMPLETION, description="Model type / modality"
    )
    supports_streaming: Optional[bool] = Field(
        default=None, description="Flag indicating support for SSE token streaming (None = not reported by upstream)"
    )
    supports_tools: Optional[bool] = Field(
        default=None, description="Flag indicating native tool/function calling support (None = not reported)"
    )
    supports_vision: Optional[bool] = Field(
        default=None, description="Flag indicating multimodal vision (image input) support (None = not reported)"
    )
    supports_json_mode: Optional[bool] = Field(
        default=None, description="Flag indicating enforced JSON schema / structured output support (None = not reported)"
    )
    supports_reasoning: Optional[bool] = Field(
        default=None, description="Flag indicating extended reasoning / chain-of-thought token extraction (None = not reported)"
    )
    max_input_tokens: Optional[int] = Field(
        default=None, gt=0, description="Maximum allowable prompt / context window token count"
    )
    max_output_tokens: Optional[int] = Field(
        default=None, gt=0, description="Maximum allowable completion generation token count"
    )
    default_temperature: Optional[float] = Field(
        default=None, ge=0.0, le=2.0, description="Recommended default generation temperature (None = not reported)"
    )
    input_cost_per_million: Optional[float] = Field(
        default=None, ge=0.0, description="Estimated USD cost per 1,000,000 input prompt tokens"
    )
    output_cost_per_million: Optional[float] = Field(
        default=None, ge=0.0, description="Estimated USD cost per 1,000,000 completion tokens"
    )
    is_enabled: bool = Field(
        default=True, description="Admin toggle to enable/disable model from agent selection"
    )
    is_default: bool = Field(
        default=False, description="Flag indicating default model for the project in this model type"
    )
    is_deleted: bool = Field(
        default=False, description="Soft-delete status indicator"
    )
    deleted_at: Optional[datetime] = Field(
        default=None, description="Soft-deletion timestamp"
    )
    revision: int = Field(
        default=1, description="Optimistic Concurrency Control (OCC) revision counter"
    )

    class Settings:
        name = "project_models"
        indexes = [
            # Compound Unique Index: Prevents duplicate models per provider (excluding deleted)
            IndexModel(
                [("provider_id", ASCENDING), ("model_id", ASCENDING)],
                unique=True,
                partialFilterExpression={"is_deleted": False},
                name="idx_project_models_provider_model_unique",
            ),
            # Compound Index: Optimizes active model discovery
            IndexModel(
                [("project_id", ASCENDING), ("is_enabled", ASCENDING), ("is_deleted", ASCENDING)],
                name="idx_project_models_project_enabled_deleted",
            ),
            # Capability Search Index: Fast filtering for agent planners
            IndexModel(
                [
                    ("project_id", ASCENDING),
                    ("supports_tools", ASCENDING),
                    ("supports_vision", ASCENDING),
                    ("is_enabled", ASCENDING),
                ],
                name="idx_project_models_capabilities",
            ),
        ]
