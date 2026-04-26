# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenTelemetry tracing integration in StatelessKernel."""

import pytest

from agent_os.stateless import StatelessKernel, ExecutionContext, MemoryBackend

# Detect whether the OTel SDK is available for span verification
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    _HAS_OTEL_SDK = True
except ImportError:
    _HAS_OTEL_SDK = False


# Module-scoped provider so set_tracer_provider is called at most once
_exporter: "InMemorySpanExporter | None" = None


def _get_exporter() -> "InMemorySpanExporter":
    global _exporter
    if _exporter is None:
        _exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(_exporter))
        trace.set_tracer_provider(provider)
    return _exporter


@pytest.mark.skipif(not _HAS_OTEL_SDK, reason="opentelemetry SDK not installed")
class TestOTelTracing:
    """Verify that OTel spans are created for kernel operations."""

    @pytest.fixture(autouse=True)
    def otel_setup(self):
        self.exporter = _get_exporter()
        self.exporter.clear()
        yield

    @pytest.mark.asyncio
    async def test_execute_creates_span(self):
        kernel = StatelessKernel(enable_tracing=True)
        ctx = ExecutionContext(agent_id="t1", policies=[])
        await kernel.execute("ping", {}, ctx)

        spans = self.exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert "kernel.execute" in names

    @pytest.mark.asyncio
    async def test_span_has_attributes(self):
        kernel = StatelessKernel(enable_tracing=True)
        ctx = ExecutionContext(agent_id="t1", policies=[])
        await kernel.execute("ping", {}, ctx)

        spans = self.exporter.get_finished_spans()
        execute_span = [s for s in spans if s.name == "kernel.execute"][0]
        assert execute_span.attributes["operation"] == "execute"
        assert execute_span.attributes["action"] == "ping"
        assert execute_span.attributes["backend_type"] == "MemoryBackend"

    @pytest.mark.asyncio
    async def test_backend_get_creates_span(self):
        backend = MemoryBackend()
        await backend.set("ref:1", {"x": 1})
        kernel = StatelessKernel(backend=backend, enable_tracing=True)
        ctx = ExecutionContext(agent_id="t1", policies=[], state_ref="ref:1")
        await kernel.execute("ping", {}, ctx)

        span_names = [s.name for s in self.exporter.get_finished_spans()]
        assert "kernel.backend.get" in span_names

    @pytest.mark.asyncio
    async def test_no_spans_when_tracing_disabled(self):
        kernel = StatelessKernel(enable_tracing=False)
        ctx = ExecutionContext(agent_id="t1", policies=[])
        await kernel.execute("ping", {}, ctx)

        # No new spans should have been created (exporter was cleared in setup)
        assert len(self.exporter.get_finished_spans()) == 0


class TestTracingGracefulDegradation:
    """Tracing disabled gracefully when OTel is not installed."""

    @pytest.mark.asyncio
    async def test_kernel_works_without_otel(self):
        kernel = StatelessKernel(enable_tracing=False)
        ctx = ExecutionContext(agent_id="t1", policies=[])
        result = await kernel.execute("ping", {}, ctx)
        assert result.success is True
