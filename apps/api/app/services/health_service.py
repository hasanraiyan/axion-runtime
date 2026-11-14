import time
from datetime import datetime, timezone
from app.core.config import settings
from app.db.client import check_db_health
from app.schemas.health import HealthData

_start_time = time.time()


class HealthService:
    @staticmethod
    async def get_health() -> HealthData:
        uptime = round(time.time() - _start_time, 2)
        db_health = await check_db_health()
        return HealthData(
            status="ok",
            version=settings.VERSION,
            environment=settings.ENVIRONMENT,
            uptime_seconds=uptime,
            timestamp=datetime.now(timezone.utc).isoformat(),
            database=db_health.get("status"),
        )
