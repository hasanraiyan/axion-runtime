from fastapi import APIRouter
from app.schemas.common import ApiResponse
from app.schemas.health import HealthData
from app.services.health_service import HealthService

router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "",
    response_model=ApiResponse[HealthData],
    summary="Service Health Check",
    description="Check the operational status, version, and uptime of the API service.",
    operation_id="get_health_status",
)
async def get_health() -> ApiResponse[HealthData]:
    data = HealthService.get_health()
    return ApiResponse(data=data, message="Service is healthy")
