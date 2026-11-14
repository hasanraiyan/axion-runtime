from pydantic import BaseModel, Field


class HealthData(BaseModel):
    status: str = Field(default="ok", description="Overall service status")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Running environment")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    timestamp: str = Field(..., description="Current ISO timestamp")
