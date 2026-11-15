"""
OpenTelemetry adapter for the ``TelemetryPort`` tracer (SRS-07 NFR-O). Uses only the OpenTelemetry *API*, which is a
no-op until the deployment installs and configures an SDK/exporter, so Axion never forces an exporter on anyone.
The import is optional: without the API package everything degrades to ``NullTelemetry``.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

try:  # pragma: no cover - exercised either way depending on the environment
    from opentelemetry import propagate, trace
    from opentelemetry.trace import Status, StatusCode

    AVAILABLE = True
except Exception:  # pragma: no cover
    AVAILABLE = False

from app.core.tools.telemetry import NullTelemetry

logger = logging.getLogger(__name__)
SCOPE = "axion.tools"


class _Span:
    def __init__(self, span: Any) -> None:
        self._span = span
        context = span.get_span_context()
        self.trace_id: Optional[str] = format(context.trace_id, "032x") if context.is_valid else None

    def set_attribute(self, key: str, value: Any) -> None:
        if isinstance(value, (str, bool, int, float)):  # never structured data: it could hold arguments or results
            self._span.set_attribute(key, value)

    def record_error(self, error: BaseException) -> None:
        self._span.set_status(Status(StatusCode.ERROR, type(error).__name__))  # the class only, never the message


class OtelTracer:
    def __init__(self) -> None:
        self._tracer = trace.get_tracer(SCOPE)

    @contextmanager
    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[_Span]:
        with self._tracer.start_as_current_span(name) as span:
            handle = _Span(span)
            for key, value in (attributes or {}).items():
                handle.set_attribute(key, value)
            yield handle


def build_tracer() -> Any:
    return OtelTracer() if AVAILABLE else NullTelemetry()


def inject_trace_context(headers: Dict[str, str]) -> None:
    """Add W3C ``traceparent`` to outbound headers when a valid span is active (no-op otherwise)."""
    if not AVAILABLE:
        return
    try:
        propagate.inject(headers)
    except Exception:  # tracing must never break a request
        logger.debug("trace context injection failed", exc_info=True)
