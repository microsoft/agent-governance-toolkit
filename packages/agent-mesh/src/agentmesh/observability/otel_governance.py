# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry tracing for governance events.

Exports OTEL spans for every policy decision, trust evaluation,
signal delivery, and audit event in the governance toolkit.  All
recording methods are safe no-ops when ``opentelemetry`` is not
installed.
"""

from __future__ import annotations

import time
from typing import Any

# ---------------------------------------------------------------------------
# Conditional OpenTelemetry imports
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider  # noqa: F401
    from opentelemetry.sdk.resources import Resource  # noqa: F401

    _OTEL_AVAILABLE = True
except ImportError:
    pass


class GovernanceTracer:
    """OpenTelemetry tracer for governance events.

    Exports OTEL spans for every policy decision, trust evaluation,
    and security event in the governance toolkit.

    All methods are safe no-ops when ``opentelemetry-api`` /
    ``opentelemetry-sdk`` are not installed, so the class can always be
    imported and instantiated.

    Args:
        service_name: Service name written into the OTel resource.
            Defaults to ``"agent-governance-toolkit"``.
        tracer_provider: An explicit ``TracerProvider``.  When *None*
            the global provider is used.

    Example::

        tracer = GovernanceTracer()
        tracer.trace_policy_decision(
            policy_name="max-delegation-depth",
            decision={"action": "DENY", "reason": "depth exceeded"},
            context={"agent_did": "did:mesh:abc"},
        )
    """

    def __init__(
        self,
        service_name: str = "agent-governance-toolkit",
        tracer_provider: Any = None,
    ) -> None:
        self._service_name = service_name
        self._tracer: Any = None

        if _OTEL_AVAILABLE:
            if tracer_provider is not None:
                self._tracer = tracer_provider.get_tracer(service_name)
            else:
                self._tracer = trace.get_tracer(service_name)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return ``True`` when OpenTelemetry is available."""
        return self._tracer is not None

    # ------------------------------------------------------------------
    # Public tracing methods
    # ------------------------------------------------------------------

    def trace_policy_decision(
        self,
        policy_name: str,
        decision: dict,
        context: dict,
    ) -> None:
        """Create an OTEL span for a policy decision.

        Args:
            policy_name: Identifier of the policy that was evaluated.
            decision: Dict containing at least ``action`` (e.g.
                ``"ALLOW"`` / ``"DENY"``) and optionally ``reason``.
            context: Arbitrary context dict.  Keys such as
                ``agent_did``, ``resource``, or ``namespace`` are
                promoted to span attributes.
        """
        if not self.enabled:
            return

        with self._tracer.start_as_current_span(
            "mesh.governance.policy_decision"
        ) as span:
            start = time.perf_counter()
            span.set_attribute("policy.name", policy_name)
            span.set_attribute(
                "policy.decision", str(decision.get("action", "unknown"))
            )
            if "reason" in decision:
                span.set_attribute("policy.reason", str(decision["reason"]))

            # Promote well-known context keys to attributes
            for key in ("agent_did", "resource", "namespace"):
                if key in context:
                    span.set_attribute(f"governance.{key}", str(context[key]))

            elapsed = (time.perf_counter() - start) * 1000
            span.set_attribute("mesh.operation.duration_ms", elapsed)

    def trace_trust_evaluation(
        self,
        agent_did: str,
        trust_score: float,
        decision: str,
    ) -> None:
        """Create a span for trust score evaluation.

        Args:
            agent_did: DID of the agent whose trust was evaluated.
            trust_score: Computed trust score.
            decision: Resulting decision (e.g. ``"trusted"`` /
                ``"untrusted"`` / ``"probation"``).
        """
        if not self.enabled:
            return

        with self._tracer.start_as_current_span(
            "mesh.governance.trust_evaluation"
        ) as span:
            start = time.perf_counter()
            span.set_attribute("agent.did", agent_did)
            span.set_attribute("agent.trust_score", trust_score)
            span.set_attribute("governance.trust.decision", decision)
            elapsed = (time.perf_counter() - start) * 1000
            span.set_attribute("mesh.operation.duration_ms", elapsed)

    def trace_signal_delivery(
        self,
        agent_id: str,
        signal_name: str,
        reason: str,
    ) -> None:
        """Trace agent signal delivery (SIGKILL, SIGPOLICY, etc.).

        Args:
            agent_id: Identifier of the target agent.
            signal_name: Signal name, e.g. ``"SIGKILL"`` or
                ``"SIGPOLICY"``.
            reason: Human-readable reason for the signal.
        """
        if not self.enabled:
            return

        with self._tracer.start_as_current_span(
            "mesh.governance.signal_delivery"
        ) as span:
            start = time.perf_counter()
            span.set_attribute("agent.id", agent_id)
            span.set_attribute("governance.signal.name", signal_name)
            span.set_attribute("governance.signal.reason", reason)
            elapsed = (time.perf_counter() - start) * 1000
            span.set_attribute("mesh.operation.duration_ms", elapsed)

    def trace_audit_event(
        self,
        entry_id: str,
        event_type: str,
        agent_did: str,
    ) -> None:
        """Trace audit log entries.

        Args:
            entry_id: Unique identifier for the audit entry.
            event_type: Type of the audit event (e.g.
                ``"policy_violation"`` or ``"trust_update"``).
            agent_did: DID of the agent associated with the event.
        """
        if not self.enabled:
            return

        with self._tracer.start_as_current_span(
            "mesh.governance.audit_event"
        ) as span:
            start = time.perf_counter()
            span.set_attribute("audit.entry_id", entry_id)
            span.set_attribute("audit.event_type", event_type)
            span.set_attribute("agent.did", agent_did)
            elapsed = (time.perf_counter() - start) * 1000
            span.set_attribute("mesh.operation.duration_ms", elapsed)
