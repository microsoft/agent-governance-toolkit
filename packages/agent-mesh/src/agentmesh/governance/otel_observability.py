# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenTelemetry native observability for AGT governance operations.

Emits spans and metrics from PolicyEngine, TrustManager, and approval
workflows. Zero overhead when OTel is not configured (no-op provider).

Usage::

    from agentmesh.governance.otel_observability import enable_otel

    enable_otel(service_name="my-governed-agent")
    # All governance operations now emit OTel spans and metrics
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Lazy-loaded OTel modules — zero import cost if unused
_tracer = None
_meter = None
_counters: dict[str, Any] = {}
_histograms: dict[str, Any] = {}
_initialized = False

# Semantic attribute names for AGT governance
ATTR_POLICY_RULE = "agt.policy.rule"
ATTR_POLICY_ACTION = "agt.policy.action"
ATTR_POLICY_STAGE = "agt.policy.stage"
ATTR_POLICY_NAME = "agt.policy.name"
ATTR_AGENT_ID = "agt.agent.id"
ATTR_TRUST_SCORE = "agt.trust.score"
ATTR_TRUST_TIER = "agt.trust.tier"
ATTR_TOOL_NAME = "agt.tool.name"
ATTR_APPROVAL_APPROVER = "agt.approval.approver"
ATTR_APPROVAL_OUTCOME = "agt.approval.outcome"


def enable_otel(
    service_name: str = "agt-governance",
    endpoint: Optional[str] = None,
) -> None:
    """Enable OpenTelemetry instrumentation for AGT.

    Call once at application startup. If OTel SDK is not installed,
    this is a no-op with a warning.

    Args:
        service_name: Service name for OTel resource.
        endpoint: OTLP endpoint URL. If None, uses env vars
            (OTEL_EXPORTER_OTLP_ENDPOINT) or default localhost:4317.
    """
    global _tracer, _meter, _counters, _histograms, _initialized

    if _initialized:
        return

    try:
        from opentelemetry import trace, metrics
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        logger.warning(
            "opentelemetry-sdk not installed — OTel observability disabled. "
            "Install with: pip install opentelemetry-sdk opentelemetry-api"
        )
        _initialized = True
        return

    resource = Resource.create({"service.name": service_name})

    # Tracer
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("agentmesh.governance", "1.0.0")

    # Meter
    meter_provider = MeterProvider(resource=resource)
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter("agentmesh.governance", "1.0.0")

    # Counters
    _counters["evaluations"] = _meter.create_counter(
        "agt.policy.evaluations",
        description="Total policy evaluations",
        unit="1",
    )
    _counters["denials"] = _meter.create_counter(
        "agt.policy.denials",
        description="Total policy denials",
        unit="1",
    )
    _counters["approvals_requested"] = _meter.create_counter(
        "agt.approval.requests",
        description="Total approval requests",
        unit="1",
    )

    # Histograms
    _histograms["eval_latency"] = _meter.create_histogram(
        "agt.policy.latency_ms",
        description="Policy evaluation latency in milliseconds",
        unit="ms",
    )

    _initialized = True
    logger.info("AGT OTel observability enabled (service=%s)", service_name)


@contextmanager
def trace_policy_evaluation(
    agent_id: str = "",
    stage: str = "pre_tool",
    context: Optional[dict] = None,
):
    """Context manager that wraps a policy evaluation with an OTel span.

    Yields a dict that the caller populates with results (rule, action, etc.).
    On exit, the span is annotated with the results and metrics are recorded.

    Usage::

        with trace_policy_evaluation(agent_id="a1", stage="pre_tool") as result:
            decision = engine.evaluate(agent_id, ctx, stage=stage)
            result["action"] = decision.action
            result["rule"] = decision.matched_rule
            result["allowed"] = decision.allowed
    """
    result: dict[str, Any] = {}
    start = time.monotonic()

    if _tracer:
        from opentelemetry import trace

        with _tracer.start_as_current_span("agt.policy.evaluate") as span:
            span.set_attribute(ATTR_AGENT_ID, agent_id)
            span.set_attribute(ATTR_POLICY_STAGE, stage)

            try:
                yield result
            finally:
                elapsed_ms = (time.monotonic() - start) * 1000
                action = result.get("action", "unknown")
                rule = result.get("rule", "")

                span.set_attribute(ATTR_POLICY_ACTION, action)
                span.set_attribute(ATTR_POLICY_RULE, rule or "none")
                if result.get("policy_name"):
                    span.set_attribute(ATTR_POLICY_NAME, result["policy_name"])

                if not result.get("allowed", True):
                    span.set_status(trace.Status(trace.StatusCode.OK, f"Denied by {rule}"))

                _record_metrics(action, rule, stage, elapsed_ms)
    else:
        try:
            yield result
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000
            _record_metrics(
                result.get("action", "unknown"),
                result.get("rule", ""),
                stage,
                elapsed_ms,
            )


@contextmanager
def trace_approval(agent_id: str = "", rule_name: str = ""):
    """Context manager for tracing approval workflow spans."""
    result: dict[str, Any] = {}

    if _tracer:
        with _tracer.start_as_current_span("agt.approval.request") as span:
            span.set_attribute(ATTR_AGENT_ID, agent_id)
            span.set_attribute(ATTR_POLICY_RULE, rule_name)
            try:
                yield result
            finally:
                span.set_attribute(ATTR_APPROVAL_OUTCOME, result.get("outcome", "unknown"))
                span.set_attribute(ATTR_APPROVAL_APPROVER, result.get("approver", ""))

                if _counters.get("approvals_requested"):
                    _counters["approvals_requested"].add(1, {
                        ATTR_POLICY_RULE: rule_name,
                        ATTR_APPROVAL_OUTCOME: result.get("outcome", "unknown"),
                    })
    else:
        yield result


@contextmanager
def trace_trust_verification(agent_id: str = ""):
    """Context manager for tracing trust verification spans."""
    result: dict[str, Any] = {}

    if _tracer:
        with _tracer.start_as_current_span("agt.trust.verify") as span:
            span.set_attribute(ATTR_AGENT_ID, agent_id)
            try:
                yield result
            finally:
                if "score" in result:
                    span.set_attribute(ATTR_TRUST_SCORE, result["score"])
                if "tier" in result:
                    span.set_attribute(ATTR_TRUST_TIER, result["tier"])
    else:
        yield result


def record_denial(rule_name: str = "", tool_name: str = "", stage: str = "pre_tool"):
    """Record a policy denial metric."""
    if _counters.get("denials"):
        _counters["denials"].add(1, {
            ATTR_POLICY_RULE: rule_name,
            ATTR_TOOL_NAME: tool_name,
            ATTR_POLICY_STAGE: stage,
        })


def _record_metrics(action: str, rule: str, stage: str, elapsed_ms: float):
    """Record evaluation metrics."""
    labels = {
        ATTR_POLICY_ACTION: action,
        ATTR_POLICY_STAGE: stage,
    }

    if _counters.get("evaluations"):
        _counters["evaluations"].add(1, labels)

    if _histograms.get("eval_latency"):
        _histograms["eval_latency"].record(elapsed_ms, labels)

    if action == "deny" and _counters.get("denials"):
        _counters["denials"].add(1, {
            ATTR_POLICY_RULE: rule or "unknown",
            ATTR_POLICY_STAGE: stage,
        })


def is_enabled() -> bool:
    """Check if OTel observability is enabled and functional."""
    return _initialized and _tracer is not None


def reset():
    """Reset OTel state (for testing only)."""
    global _tracer, _meter, _counters, _histograms, _initialized
    _tracer = None
    _meter = None
    _counters = {}
    _histograms = {}
    _initialized = False
