from typing import List, Optional
from beanie import PydanticObjectId
from pydantic import Field
from pymongo import ASCENDING, IndexModel

from app.db.base import BaseDocument


class ProjectRoutingPolicy(BaseDocument):
    """
    Model Routing Policy defining primary and ordered fallback models for resilient execution
    (SRS-06 Section 4.3 & FR-07).
    """

    project_id: PydanticObjectId = Field(
        ..., description="Foreign key binding policy strictly to an Axion Project"
    )
    name: str = Field(
        ..., min_length=1, max_length=100, description="Friendly policy name (e.g. 'Primary Reasoning with Failover')"
    )
    description: Optional[str] = Field(
        default=None, max_length=500, description="Notes on routing purpose"
    )
    primary_model_id: PydanticObjectId = Field(
        ..., description="Foreign key to project_models representing first-choice model"
    )
    fallback_model_ids: List[PydanticObjectId] = Field(
        default_factory=list, max_length=5, description="Ordered list of backup models to try on upstream failure"
    )
    retry_timeout_ms: int = Field(
        default=3000, ge=100, description="Latency threshold after which fallback candidate is triggered"
    )
    fallback_on_codes: List[int] = Field(
        default_factory=lambda: [429, 500, 502, 503],
        description="Upstream HTTP status codes triggering fallback switch",
    )
    is_active: bool = Field(
        default=True, description="Active toggle for this policy"
    )
    revision: int = Field(
        default=1, description="Optimistic Concurrency Control (OCC) revision counter"
    )

    class Settings:
        name = "project_routing_policies"
        indexes = [
            # Compound Query Index: Fast lookup of active policies for a project
            IndexModel(
                [("project_id", ASCENDING), ("is_active", ASCENDING)],
                name="idx_project_routing_policies_project_active",
            ),
        ]
