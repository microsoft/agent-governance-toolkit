# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cross-SDK OpenTelemetry instrumentation for governance operations.

Provides :class:`GovernanceInstrumentor` that emits spans and metrics
for policy evaluation, trust updates, audit appends, and identity
operations. Falls back to no-ops when ``opentelemetry-api`` is not
installed.
"""

from __future__ import annotations

import contextlib
from typing import Any, Generator

try:
    from opentelemetry import metrics, trace

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


@contextlib.contextmanager
def _noop_span(*_args: Any, **_kwargs: Any) -> Generator[None, None, None]:
    yield


class GovernanceInstrumentor:
    """Instruments AGT governance operations with OpenTelemetry."""

    def __init__(self, service_name: str = "agentmesh", enabled: bool = True) -> None:
        self._enabled = enabled and _HAS_OTEL
        if self._enabled:
            self._tracer = trace.get_tracer(service_name)
            meter = metrics.get_meter(service_name)
            self._policy_counter = meter.create_counter(
                "agt.policy_decisions", description="Policy decisions"
            )
            self._policy_latency = meter.create_histogram(
                "agt.policy_latency_ms", unit="ms", description="Policy eval latency"
            )
            self._trust_gauge = meter.create_up_down_counter(
                "agt.trust_score_updates", description="Trust score updates"
            )
            self._audit_counter = meter.create_counter(
                "agt.audit_entries", description="Audit entries appended"
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    @contextlib.contextmanager
    def trace_policy_evaluation(self, action: str, agent_id: str) -> Generator[None, None, None]:
        if not self._enabled:
            yield
            return
        with self._tracer.start_as_current_span(
            "agt.policy.evaluate",
            attributes={"agt.action": action, "agt.agent_id": agent_id},
        ):
            yield

    @contextlib.contextmanager
    def trace_trust_update(self, agent_id: str, old_score: float, new_score: float) -> Generator[None, None, None]:
        if not self._enabled:
            yield
            return
        with self._tracer.start_as_current_span(
            "agt.trust.update",
            attributes={"agt.agent_id": agent_id, "agt.old_score": old_score, "agt.new_score": new_score},
        ):
            yield

    @contextlib.contextmanager
    def trace_audit_append(self, entry_seq: int) -> Generator[None, None, None]:
        if not self._enabled:
            yield
            return
        with self._tracer.start_as_current_span(
            "agt.audit.append", attributes={"agt.seq": entry_seq}
        ):
            yield

    @contextlib.contextmanager
    def trace_identity_operation(self, op: str, did: str) -> Generator[None, None, None]:
        if not self._enabled:
            yield
            return
        with self._tracer.start_as_current_span(
            f"agt.identity.{op}", attributes={"agt.did": did}
        ):
            yield

    def record_policy_decision(self, decision: str, duration_ms: float) -> None:
        if not self._enabled:
            return
        self._policy_counter.add(1, {"decision": decision})
        self._policy_latency.record(duration_ms)

    def record_trust_score(self, agent_id: str, score: float) -> None:
        if not self._enabled:
            return
        self._trust_gauge.add(1, {"agent_id": agent_id, "score": str(score)})

    def record_audit_chain_length(self, length: int) -> None:
        if not self._enabled:
            return
        self._audit_counter.add(1, {"chain_length": str(length)})
