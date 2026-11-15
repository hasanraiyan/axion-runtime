"""
Metrics, tracing hooks, and ``/metrics`` for MOD-07 (SRS-07 NFR-O).

The OpenTelemetry SDK is not a dependency, so spans are verified through a recording ``TelemetryPort`` tracer and the
adapter is exercised against the API's no-op tracer.
"""
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

import httpx2
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.outbound import OutboundUrlGuard
from app.core.tools.telemetry import ALLOWED_LABELS, MetricsRegistry, NullTelemetry, Telemetry
from app.integrations.guarded_transport import GuardedAsyncTransport
from app.integrations.telemetry import OtelTracer, build_tracer
from app.main import app
from tests.test_tools_services import MEMBER, ready, req
from tests.tools_harness import StaticResolver, make_harness, tool

pytestmark = pytest.mark.usefixtures("tool_models")


class RecordingTracer:
    def __init__(self) -> None:
        self.spans: List[Dict[str, Any]] = []

    @contextmanager
    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        record: Dict[str, Any] = {"name": name, "attributes": dict(attributes or {}), "errors": []}
        self.spans.append(record)

        class Handle:
            trace_id = "0af7651916cd43dd8448eb211c80319c"

            def set_attribute(self, key: str, value: Any) -> None:
                record["attributes"][key] = value

            def record_error(self, error: BaseException) -> None:
                record["errors"].append(type(error).__name__)

        yield Handle()


def instrument(h) -> RecordingTracer:
    tracer = RecordingTracer()
    h.shared.telemetry._tracer = tracer  # noqa: SLF001
    return tracer


# ====================================================================== registry
def test_counters_and_histograms_render_in_prometheus_format():
    m = MetricsRegistry(buckets=(0.1, 1.0))
    m.count("axion_x_total", {"status": "ok"})
    m.count("axion_x_total", {"status": "ok"}, 2)
    m.observe("axion_x_seconds", 0.05, {"integration_type": "mcp"})
    m.observe("axion_x_seconds", 0.5, {"integration_type": "mcp"})
    text = m.render()
    assert 'axion_x_total{status="ok"} 3' in text
    assert 'axion_x_seconds_bucket{integration_type="mcp",le="0.1"} 1' in text
    assert 'axion_x_seconds_bucket{integration_type="mcp",le="1"} 2' in text
    assert 'axion_x_seconds_bucket{integration_type="mcp",le="+Inf"} 2' in text
    assert 'axion_x_seconds_count{integration_type="mcp"} 2' in text and "# TYPE axion_x_total counter" in text


def test_tenant_identifying_and_unbounded_labels_are_refused():
    m = MetricsRegistry()
    for bad in ("project_id", "tool_key", "user_id", "subject", "integration_id", "error_message"):
        with pytest.raises(ValueError):
            m.count("axion_x_total", {bad: "v"})
    assert not {"project_id", "tool_key", "user_id", "subject", "integration_id"} & ALLOWED_LABELS


def test_label_values_are_escaped_and_truncated():
    m = MetricsRegistry()
    m.count("axion_x_total", {"status": 'a"b\nc' + "z" * 200})
    line = [x for x in m.render().splitlines() if x.startswith("axion_x_total")][0]
    assert '\\"' in line and "\\n" in line and len(line) < 120


def test_series_count_is_bounded():
    m = MetricsRegistry(max_series=3)
    for i in range(10):
        m.count("axion_x_total", {"status": str(i)})
    assert m.render().count("axion_x_total{") == 3
    m.count("axion_x_total", {"status": "0"})  # an existing series still updates
    assert m.value("axion_x_total", {"status": "0"}) == 2


def test_the_facade_never_raises_into_the_caller():
    t = Telemetry()
    t.count("axion_x_total", {"project_id": "p"})  # a programming error is logged, not thrown at a tool call
    t.observe("axion_x_seconds", 1.0, {"tool_key": "t"})


# ====================================================================== gateway wiring
async def test_an_invocation_counts_times_and_traces_without_tenant_data():
    h = make_harness()
    tracer = instrument(h)
    await ready(h, [tool("a")])
    ok = await h.container.gateway.invoke(req(h, "svc.a", {"q": "super-secret-argument"}))
    assert ok.ok
    m = h.shared.telemetry.metrics
    custom = "custom"
    assert m.value("axion_tool_invocations_total", {"integration_type": custom, "status": "ok"}) == 1
    assert m.histogram_count("axion_tool_invocation_seconds", {"integration_type": custom}) == 1
    text = m.render()
    assert "super-secret-argument" not in text and h.pid not in text and "svc.a" not in text

    spans = {s["name"]: s for s in tracer.spans}
    assert spans["tool.invoke"]["attributes"]["tool.status"] == "ok"
    assert "integration.execute" in spans
    assert "super-secret-argument" not in repr(tracer.spans) and h.pid not in repr(tracer.spans)


async def test_failures_are_counted_by_status_and_recorded_on_the_span():
    h = make_harness()
    tracer = instrument(h)
    await ready(h, [tool("a")])
    h.scripted.raise_on_execute = RuntimeError("password=hunter2")
    result = await h.container.gateway.invoke(req(h, "svc.a", {"q": "x"}))
    assert not result.ok
    m = h.shared.telemetry.metrics
    assert m.value("axion_tool_invocations_total", {"integration_type": "custom", "status": result.status.value}) == 1
    execute = next(s for s in tracer.spans if s["name"] == "integration.execute")
    assert execute["errors"] == ["RuntimeError"] and "hunter2" not in repr(tracer.spans)


async def test_a_refused_call_before_resolution_is_counted_as_unknown_type():
    h = make_harness()
    result = await h.container.gateway.invoke(req(h, "svc.ghost", {}))
    assert not result.ok
    assert h.shared.telemetry.metrics.value("axion_tool_invocations_total", {"integration_type": "unknown", "status": result.status.value}) == 1


async def test_the_trace_id_is_stored_on_the_invocation_record():
    h = make_harness()
    instrument(h)
    await ready(h, [tool("a")])
    await h.container.gateway.invoke(req(h, "svc.a", {"q": "x"}))
    assert [i.trace_id for i in h.invocations.items] == ["0af7651916cd43dd8448eb211c80319c"]


async def test_discovery_and_the_toolset_cache_are_counted():
    h = make_harness()
    tracer = instrument(h)
    await ready(h, [tool("a"), tool("b")])
    m = h.shared.telemetry.metrics
    assert m.value("axion_tool_discovery_total", {"integration_type": "custom", "outcome": "ok"}) >= 1
    assert any(s["name"] == "integration.discover" for s in tracer.spans)
    p = h.principal(MEMBER)
    await h.container.toolset.resolve_toolset(p)
    await h.container.toolset.resolve_toolset(p)
    assert m.value("axion_toolset_cache_total", {"result": "miss"}) == 1 and m.value("axion_toolset_cache_total", {"result": "hit"}) == 1


async def test_telemetry_is_optional_for_every_component():
    h = make_harness()
    h.shared.telemetry = NullTelemetry()  # type: ignore[assignment]
    from app.services.tools.gateway import ToolExecutionGateway

    gateway = ToolExecutionGateway(h.container.gateway._stages, h.container.gateway._recorder)  # noqa: SLF001
    await ready(h, [tool("a")])
    assert (await gateway.invoke(req(h, "svc.a", {"q": "x"}))).ok


# ====================================================================== OpenTelemetry adapter and propagation
def test_the_otel_adapter_works_with_the_apis_noop_tracer():
    tracer = build_tracer()
    if not isinstance(tracer, OtelTracer):
        pytest.skip("opentelemetry-api is not installed")
    with tracer.span("x", {"ok": 1, "bad": {"nested": "arguments"}}) as span:
        span.set_attribute("also_bad", [1, 2])
        span.record_error(ValueError("secret message"))
        assert span.trace_id is None  # the no-op tracer has no valid trace


async def test_an_active_trace_is_propagated_to_the_upstream_as_traceparent(monkeypatch):
    seen: Dict[str, str] = {}

    class Inner(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            seen.update(request.headers)
            return httpx2.Response(200)

    def inject(carrier: Dict[str, str]) -> None:
        carrier["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        carrier["baggage"] = "tenant=acme"  # must never be forwarded

    monkeypatch.setattr("app.integrations.guarded_transport.inject_trace_context", inject)
    transport = GuardedAsyncTransport(OutboundUrlGuard(StaticResolver()), inner=Inner())
    async with httpx2.AsyncClient(transport=transport) as client:
        await client.get("https://mcp.example.com/mcp")
    assert seen["traceparent"].startswith("00-0af7651916cd43dd8448eb211c80319c")
    assert "baggage" not in seen


# ====================================================================== /metrics
def test_metrics_is_hidden_unless_a_token_is_configured(monkeypatch):
    monkeypatch.setattr(settings, "METRICS_TOKEN", "")
    assert TestClient(app).get("/metrics").status_code == 404


def test_metrics_requires_the_bearer_token(monkeypatch):
    monkeypatch.setattr(settings, "METRICS_TOKEN", "scrape-token")
    client = TestClient(app)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-token"})
    assert ok.status_code == 200 and ok.headers["content-type"].startswith("text/plain")


def test_metrics_is_not_part_of_the_openapi_contract():
    assert "/metrics" not in app.openapi()["paths"]


def test_span_handles_only_accept_scalar_attributes_and_never_leak_error_messages():
    from app.integrations.telemetry import AVAILABLE, _Span

    if not AVAILABLE:
        pytest.skip("opentelemetry-api is not installed")

    class Ctx:
        is_valid = True
        trace_id = 0x0AF7651916CD43DD8448EB211C80319C

    class FakeSpan:
        def __init__(self) -> None:
            self.attributes: Dict[str, Any] = {}
            self.status: Any = None

        def get_span_context(self) -> Ctx:
            return Ctx()

        def set_attribute(self, key: str, value: Any) -> None:
            self.attributes[key] = value

        def set_status(self, status: Any) -> None:
            self.status = status

    fake = FakeSpan()
    handle = _Span(fake)
    assert handle.trace_id == "0af7651916cd43dd8448eb211c80319c"
    handle.set_attribute("ok", "v")
    handle.set_attribute("n", 3)
    handle.set_attribute("bad", {"arguments": "x"})
    handle.set_attribute("worse", ["a"])
    assert fake.attributes == {"ok": "v", "n": 3}
    handle.record_error(ValueError("password=hunter2"))
    assert fake.status.description == "ValueError"  # the class name only, never the message


def test_label_values_with_quotes_and_newlines_cannot_forge_series():
    m = MetricsRegistry()
    m.count("axion_x_total", {"status": 'x"} 99\naxion_forged_total{a="b'})
    assert "\naxion_forged_total" not in m.render()
