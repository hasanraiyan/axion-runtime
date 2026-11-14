import logging
import sys
import json
from datetime import datetime, timezone
from contextvars import ContextVar
from typing import Optional

# Context variable to correlate logs with the active request ID
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for production logging."""

    def format(self, record: logging.LogRecord) -> str:
        raw_msg = record.getMessage()

        # If the message is already a JSON string (e.g., from PyMongo internal logging),
        # parse it so it isn't double-escaped with backslashes (\") inside the outer JSON payload
        message_val: object = raw_msg
        if isinstance(raw_msg, str) and raw_msg.startswith("{") and raw_msg.endswith("}"):
            try:
                message_val = json.loads(raw_msg)
            except Exception:
                message_val = raw_msg

        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": message_val,
            "logger": record.name,
        }

        req_id = request_id_ctx.get()
        if req_id:
            log_obj["request_id"] = req_id

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure root logger with structured output."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Avoid duplicate handlers if reloaded
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        root_logger.addHandler(handler)

    # Silence noisy third-party loggers (e.g. pymongo topology/heartbeats, uvicorn access, httpx)
    noisy_loggers = [
        "uvicorn.access",
        "pymongo",
        "pymongo.topology",
        "pymongo.connection",
        "pymongo.serverSelection",
        "pymongo.command",
        "motor",
        "asyncio",
        "httpcore",
        "httpx",
    ]
    for noisy in noisy_loggers:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logging.getLogger("app")


logger = logging.getLogger("app")
