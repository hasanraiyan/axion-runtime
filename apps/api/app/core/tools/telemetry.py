"""
Telemetry port, metrics, and tracing facade for MOD-07 (SRS-07 NFR-O).

* ``TelemetryPort`` is what services depend on (DIP). ``NullTelemetry`` is the default so nothing needs telemetry to run.
* ``MetricsRegistry`` is a small in-process registry that renders the Prometheus text format. It only accepts the label
  names in ``ALLOWED_LABELS``: project ids, tool keys, and user ids are unbounded and would both explode the series count
  and leak tenant data to whoever can read ``/metrics``. Per-tenant detail belongs in invocation records and audit logs.
* Spans go through a ``Tracer`` supplied by ``app.integrations.telemetry`` (OpenTelemetry when installed).
  Span attributes follow the same rule as metric labels and never carry arguments, results, or credentials.
"""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)

ALLOWED_LABELS = frozenset({"integration_type", "status", "outcome", "result", "grant", "transport", "kind"})
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)

LabelKey = Tuple[Tuple[str, str], ...]


class SpanHandle(Protocol):
    trace_id: Optional[str]

    def set_attribute(self, key: str, value: Any) -> None: ...

    def record_error(self, error: BaseException) -> None: ...


class TelemetryPort(Protocol):
    def count(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None: ...

    def observe(self, name: str, seconds: float, labels: Optional[Dict[str, str]] = None) -> None: ...

    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Any:
        """A context manager yielding a ``SpanHandle``."""
        ...


class _NullSpan:
    trace_id: Optional[str] = None

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def record_error(self, error: BaseException) -> None:
        return None


class NullTelemetry:
    def count(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        return None

    def observe(self, name: str, seconds: float, labels: Optional[Dict[str, str]] = None) -> None:
        return None

    @contextmanager
    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[_NullSpan]:
        yield _NullSpan()


def _key(labels: Optional[Dict[str, str]]) -> LabelKey:
    labels = labels or {}
    unknown = set(labels) - ALLOWED_LABELS
    if unknown:
        raise ValueError(f"Metric label not allowed (unbounded or tenant-identifying): {sorted(unknown)[0]}")
    return tuple(sorted((k, str(v)[:60]) for k, v in labels.items()))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(key: LabelKey, extra: Optional[Tuple[str, str]] = None) -> str:
    pairs = list(key) + ([extra] if extra else [])
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in pairs) + "}" if pairs else ""


class MetricsRegistry:
    def __init__(self, buckets: Tuple[float, ...] = DEFAULT_BUCKETS, max_series: int = 2000) -> None:
        self._buckets = buckets
        self._max_series = max_series
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[LabelKey, float]] = {}
        self._histograms: Dict[str, Dict[LabelKey, List[float]]] = {}  # [bucket counts..., +Inf, sum]

    def _room(self, table: Dict[str, Dict[LabelKey, Any]], name: str, key: LabelKey) -> bool:
        series = table.setdefault(name, {})
        return key in series or sum(len(v) for v in table.values()) < self._max_series

    def count(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        key = _key(labels)
        with self._lock:
            if self._room(self._counters, name, key):
                series = self._counters[name]
                series[key] = series.get(key, 0.0) + value

    def observe(self, name: str, seconds: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = _key(labels)
        with self._lock:
            if not self._room(self._histograms, name, key):
                return
            row = self._histograms[name].setdefault(key, [0.0] * (len(self._buckets) + 2))
            for i, bound in enumerate(self._buckets):
                if seconds <= bound:
                    row[i] += 1
            row[len(self._buckets)] += 1  # +Inf (total count)
            row[len(self._buckets) + 1] += seconds

    def value(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        return self._counters.get(name, {}).get(_key(labels), 0.0)

    def histogram_count(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        row = self._histograms.get(name, {}).get(_key(labels))
        return row[len(self._buckets)] if row else 0.0

    def render(self) -> str:
        lines: List[str] = []
        with self._lock:
            for name in sorted(self._counters):
                lines.append(f"# TYPE {name} counter")
                for key, value in sorted(self._counters[name].items()):
                    lines.append(f"{name}{_fmt(key)} {value:g}")
            for name in sorted(self._histograms):
                lines.append(f"# TYPE {name} histogram")
                for key, row in sorted(self._histograms[name].items()):
                    for i, bound in enumerate(self._buckets):
                        lines.append(f"{name}_bucket{_fmt(key, ('le', f'{bound:g}'))} {row[i]:g}")
                    lines.append(f"{name}_bucket{_fmt(key, ('le', '+Inf'))} {row[len(self._buckets)]:g}")
                    lines.append(f"{name}_sum{_fmt(key)} {row[len(self._buckets) + 1]:g}")
                    lines.append(f"{name}_count{_fmt(key)} {row[len(self._buckets)]:g}")
        return "\n".join(lines) + "\n"


class Telemetry:
    """Metrics registry plus an optional tracer; the production ``TelemetryPort``."""

    def __init__(self, metrics: Optional[MetricsRegistry] = None, tracer: Optional[Any] = None) -> None:
        self.metrics = metrics if metrics is not None else MetricsRegistry()
        self._tracer = tracer if tracer is not None else NullTelemetry()

    def count(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        try:
            self.metrics.count(name, labels, value)
        except Exception:  # a metrics bug must never fail a tool call
            logger.exception("Metric %s could not be recorded", name)

    def observe(self, name: str, seconds: float, labels: Optional[Dict[str, str]] = None) -> None:
        try:
            self.metrics.observe(name, seconds, labels)
        except Exception:
            logger.exception("Metric %s could not be recorded", name)

    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Any:
        return self._tracer.span(name, attributes)
