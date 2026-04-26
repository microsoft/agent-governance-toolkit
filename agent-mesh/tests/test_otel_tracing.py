# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenTelemetry tracing of trust operations."""

import pytest
from unittest.mock import patch, MagicMock

from agentmesh.observability.tracing import (
    MeshTracer,
    configure_tracing,
    inject_context,
    extract_context,
    _OTEL_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tracer() -> MeshTracer:
    """Return a MeshTracer backed by an in-memory span exporter."""
    if not _OTEL_AVAILABLE:
        pytest.skip("opentelemetry not installed")

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
    from opentelemetry import trace

    class _InMemoryExporter(SpanExporter):
        """Minimal in-memory exporter for testing."""

        def __init__(self):
            self._spans = []

        def export(self, spans):
            self._spans.extend(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def get_finished_spans(self):
            return list(self._spans)

    exporter = _InMemoryExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    # Force-set the global provider (bypass the "already set" guard)
    trace._TRACER_PROVIDER = None
    trace._TRACER_PROVIDER_SET_ONCE._done = False
    trace.set_tracer_provider(provider)

    tracer = MeshTracer(service_name="agentmesh-test")
    return tracer, exporter


# ---------------------------------------------------------------------------
# trace_handshake
# ---------------------------------------------------------------------------


class TestTraceHandshake:
    """Tests for the trace_handshake decorator."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_handshake
        def handshake(agent_did: str, peer_did: str) -> str:
            return "accepted"

        handshake(agent_did="did:mesh:aaa", peer_did="did:mesh:bbb")
        spans = exporter.get_finished_spans()

        assert len(spans) == 1
        assert spans[0].name == "mesh.trust.handshake"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_handshake
        def handshake(agent_did: str, peer_did: str) -> str:
            return "accepted"

        handshake(agent_did="did:mesh:aaa", peer_did="did:mesh:bbb")
        attrs = dict(exporter.get_finished_spans()[0].attributes)

        assert attrs["agent.did"] == "did:mesh:aaa"
        assert attrs["peer.did"] == "did:mesh:bbb"
        assert attrs["mesh.handshake.result"] == "accepted"
        assert "mesh.operation.duration_ms" in attrs

    def test_records_exception(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_handshake
        def bad_handshake(agent_did: str, peer_did: str) -> str:
            raise ValueError("nope")

        with pytest.raises(ValueError):
            bad_handshake(agent_did="did:mesh:aaa", peer_did="did:mesh:bbb")

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["operation.status"] == "error"
        assert attrs["error.type"] == "ValueError"


# ---------------------------------------------------------------------------
# trace_verification
# ---------------------------------------------------------------------------


class TestTraceVerification:
    """Tests for the trace_verification decorator."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_verification
        def verify(agent_did: str, method: str) -> bool:
            return True

        verify(agent_did="did:mesh:aaa", method="ed25519")
        spans = exporter.get_finished_spans()

        assert spans[0].name == "mesh.trust.verification"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_verification
        def verify(agent_did: str, method: str) -> bool:
            return True

        verify(agent_did="did:mesh:aaa", method="ed25519")
        attrs = dict(exporter.get_finished_spans()[0].attributes)

        assert attrs["agent.did"] == "did:mesh:aaa"
        assert attrs["mesh.verification.method"] == "ed25519"
        assert attrs["mesh.verification.result"] == "True"


# ---------------------------------------------------------------------------
# trace_delegation
# ---------------------------------------------------------------------------


class TestTraceDelegation:
    """Tests for the trace_delegation decorator."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_delegation
        def delegate(delegator_did: str, delegatee_did: str, chain_depth: int = 1) -> str:
            return "ok"

        delegate(delegator_did="did:mesh:aaa", delegatee_did="did:mesh:bbb", chain_depth=2)
        spans = exporter.get_finished_spans()

        assert spans[0].name == "mesh.trust.delegation"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_delegation
        def delegate(delegator_did: str, delegatee_did: str, chain_depth: int = 1) -> str:
            return "ok"

        delegate(delegator_did="did:mesh:aaa", delegatee_did="did:mesh:bbb", chain_depth=3)
        attrs = dict(exporter.get_finished_spans()[0].attributes)

        assert attrs["delegator.did"] == "did:mesh:aaa"
        assert attrs["delegatee.did"] == "did:mesh:bbb"
        assert attrs["mesh.delegation.depth"] == 3


# ---------------------------------------------------------------------------
# trace_policy_check
# ---------------------------------------------------------------------------


class TestTracePolicyCheck:
    """Tests for the trace_policy_check decorator."""

    def test_creates_span_with_correct_name(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_policy_check
        def check(policy_name: str) -> str:
            return "ALLOW"

        check(policy_name="max-delegation-depth")
        spans = exporter.get_finished_spans()

        assert spans[0].name == "mesh.governance.policy_check"

    def test_sets_correct_attributes(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_policy_check
        def check(policy_name: str) -> str:
            return "DENY"

        check(policy_name="namespace-isolation")
        attrs = dict(exporter.get_finished_spans()[0].attributes)

        assert attrs["policy.name"] == "namespace-isolation"
        assert attrs["policy.decision"] == "DENY"


# ---------------------------------------------------------------------------
# Context propagation
# ---------------------------------------------------------------------------


class TestContextPropagation:
    """Tests for inject_context / extract_context roundtrip."""

    def test_roundtrip(self):
        if not _OTEL_AVAILABLE:
            pytest.skip("opentelemetry not installed")

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
        from opentelemetry import trace

        class _Noop(SpanExporter):
            def export(self, spans):
                return SpanExportResult.SUCCESS
            def shutdown(self):
                pass

        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(_Noop()))
        trace.set_tracer_provider(provider)

        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("parent") as parent_span:
            headers: dict = {}
            inject_context(headers)

            assert "traceparent" in headers

            token = extract_context(headers)
            assert token is not None

    def test_inject_without_otel(self):
        """inject_context returns headers unchanged when OTel unavailable."""
        with patch("agentmesh.observability.tracing._OTEL_AVAILABLE", False):
            headers = {"x-custom": "val"}
            result = inject_context(headers)
            assert result == {"x-custom": "val"}

    def test_extract_without_otel(self):
        """extract_context returns None when OTel unavailable."""
        with patch("agentmesh.observability.tracing._OTEL_AVAILABLE", False):
            result = extract_context({"traceparent": "00-abc-def-01"})
            assert result is None


# ---------------------------------------------------------------------------
# Graceful degradation when OTel is not installed
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    """MeshTracer must be a no-op when OpenTelemetry is absent."""

    def test_tracer_disabled_without_otel(self):
        with patch("agentmesh.observability.tracing._OTEL_AVAILABLE", False):
            tracer = MeshTracer.__new__(MeshTracer)
            tracer._service_name = "agentmesh"
            tracer._endpoint = None
            tracer._tracer = None

            assert not tracer.enabled

    def test_decorator_passthrough_without_otel(self):
        with patch("agentmesh.observability.tracing._OTEL_AVAILABLE", False):
            tracer = MeshTracer.__new__(MeshTracer)
            tracer._service_name = "agentmesh"
            tracer._endpoint = None
            tracer._tracer = None

            @tracer.trace_handshake
            def handshake(agent_did: str, peer_did: str) -> str:
                return "accepted"

            result = handshake(agent_did="did:mesh:aaa", peer_did="did:mesh:bbb")
            assert result == "accepted"


# ---------------------------------------------------------------------------
# configure_tracing
# ---------------------------------------------------------------------------


class TestConfigureTracing:
    """Tests for the configure_tracing helper."""

    def test_returns_none_without_otel(self):
        with patch("agentmesh.observability.tracing._OTEL_AVAILABLE", False):
            assert configure_tracing() is None

    def test_console_exporter(self):
        if not _OTEL_AVAILABLE:
            pytest.skip("opentelemetry not installed")

        provider = configure_tracing(service_name="test-console", console=True)
        assert provider is not None

    def test_auto_detect_endpoint(self):
        if not _OTEL_AVAILABLE:
            pytest.skip("opentelemetry not installed")

        with patch.dict("os.environ", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}):
            provider = configure_tracing(service_name="test-env")
            assert provider is not None


# ---------------------------------------------------------------------------
# Async decorator support
# ---------------------------------------------------------------------------


class TestAsyncDecorators:
    """Verify decorators work with async functions."""

    @pytest.mark.asyncio
    async def test_async_handshake(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_handshake
        async def handshake(agent_did: str, peer_did: str) -> str:
            return "accepted"

        result = await handshake(agent_did="did:mesh:aaa", peer_did="did:mesh:bbb")
        assert result == "accepted"

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "mesh.trust.handshake"

    @pytest.mark.asyncio
    async def test_async_verification(self):
        tracer, exporter = _make_tracer()

        @tracer.trace_verification
        async def verify(agent_did: str, method: str) -> bool:
            return True

        result = await verify(agent_did="did:mesh:aaa", method="ed25519")
        assert result is True

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["mesh.verification.result"] == "True"
