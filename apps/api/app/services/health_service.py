import time
from datetime import datetime, timezone
from app.core.config import settings
from app.schemas.health import HealthData

_start_time = time.time()


class HealthService:
    @staticmethod
    def get_health() -> HealthData:
        uptime = round(time.time() - _start_time, 2)
        return HealthData(
            status="ok",
            version=settings.VERSION,
            environment=settings.ENVIRONMENT,
            uptime_seconds=uptime,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
