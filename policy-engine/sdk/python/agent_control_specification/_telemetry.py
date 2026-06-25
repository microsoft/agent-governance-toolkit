"""Host-side telemetry layer for the Agent Control Specification Python SDK.

The Rust core owns a `TelemetrySink` SPI and an OpenTelemetry metrics bridge
crate, but neither is bound into the Python surface. This module is the
pure-Python host-side equivalent that turns each `InterventionPointResult` into
a redaction-safe `TelemetryEvent` and fans it out to one or more pluggable
sinks. It mirrors the Rust field set in `core/src/telemetry.rs` and the metric
contract in `integrations/otel/src/lib.rs` so a Python host emits the same
event shape and the same `acs_intervention_*` metric names as the Rust bridge.

Redaction is the load-bearing invariant. A `TelemetryEvent` carries decision
and reason metadata, the evidence `artefact` string, and the sorted evidence
pointer `keys` only. It never carries raw prompts, tool arguments, tool
results, transform values, annotator outputs, or pointer URL values. The
`reason_code` derivation drops any free-text policy reason to `policy_reason`
so an operator-authored reason string cannot leak through telemetry.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from ._types import (
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    JsonValue,
)

_LOGGER = logging.getLogger("agent_control_specification.telemetry")

# Mirrors integrations/otel/src/lib.rs DEFAULT_OTEL_METER_NAME.
DEFAULT_OTEL_METER_NAME = "agent_control_specification"

# Mirrors integrations/otel/src/lib.rs DECISION_WIRE_STRINGS. One counter per
# wire decision so the transform path is observable alongside the rest.
_DECISION_WIRE_STRINGS = ("allow", "deny", "warn", "escalate", "transform")

# Maximum identifier length accepted as a low cardinality reason_code, matching
# core/src/runtime.rs is_identifier_reason_code.
_MAX_REASON_CODE_LEN = 96

_REASON_CODE_EXTRA_CHARS = frozenset("_-.:/")


class TelemetryEventType(str, Enum):
    """Mirror of core/src/telemetry.rs TelemetryEventType wire strings.

    The host-side layer only emits `DECISION`; the remaining variants exist so
    the Python enum is a faithful image of the Rust contract for any consumer
    that inspects `event_type`.
    """

    DECISION = "decision"
    ANNOTATOR_DISPATCH = "annotator_dispatch"
    POLICY_EVALUATION = "policy_evaluation"
    EVALUATION_TIMING = "evaluation_timing"
    INTERVENTION_POINT_TRANSFORMED = "intervention_point.transformed"
    ANNOTATOR_FAILED = "annotator_failed"
    POLICY_FAILED = "policy_failed"


def _is_identifier_reason_code(reason: str) -> bool:
    """Return True for a low cardinality, redaction-safe reason identifier.

    Reproduces core/src/runtime.rs is_identifier_reason_code. A reason qualifies
    when it is non-empty, at most 96 bytes, and built only from ASCII
    alphanumerics plus the punctuation set ``_-.:/``.
    """

    if not reason or len(reason) > _MAX_REASON_CODE_LEN:
        return False
    return all(
        char.isascii() and (char.isalnum() or char in _REASON_CODE_EXTRA_CHARS)
        for char in reason
    )


def safe_reason_code(reason: str | None) -> str | None:
    """Reduce a verdict reason to a redaction-safe telemetry reason_code.

    Reproduces core/src/runtime.rs safe_telemetry_reason_code. An
    identifier-shaped reason passes through verbatim; any free-text reason is
    collapsed to the constant ``policy_reason`` so operator-authored prose never
    reaches a sink.
    """

    if reason is None:
        return None
    if _is_identifier_reason_code(reason):
        return reason
    return "policy_reason"


def error_class_for(reason: str | None) -> str | None:
    """Derive the telemetry error_class from a verdict reason.

    Reproduces core/src/runtime.rs telemetry_error_class. A reason carrying the
    reserved ``runtime_error:`` prefix maps to the ``runtime_error`` class;
    every other reason yields no error class.
    """

    if reason is not None and reason.startswith("runtime_error:"):
        return "runtime_error"
    return None


@dataclass(frozen=True)
class TelemetryEvent:
    """Redaction-safe telemetry record mirroring core/src/telemetry.rs.

    Every field is a structurally safe label, identifier, count, or duration.
    The dataclass holds no policy-target payload, no snapshot payload, no
    annotator output, no transform value, and no pointer URL value. The
    `evidence_verification_pointer_keys` list carries the sorted pointer map
    keys only, never the URLs they map to.
    """

    event_type: TelemetryEventType
    intervention_point: InterventionPoint | str
    decision: Decision | None = None
    reason_code: str | None = None
    error_class: str | None = None
    policy_id: str | None = None
    annotators: Sequence[str] = field(default_factory=tuple)
    enforcement_mode: EnforcementMode | None = None
    duration_ms: float | None = None
    evidence_artefact: str | None = None
    evidence_verification_pointer_keys: Sequence[str] = field(default_factory=tuple)
    action_identity: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_result(
        cls,
        intervention_point: InterventionPoint | str,
        mode: EnforcementMode | None,
        result: InterventionPointResult,
        duration_ms: float | None,
        policy_id: str | None = None,
    ) -> "TelemetryEvent":
        """Build a redaction-safe decision event from an evaluation result.

        Maps the verdict decision, the redaction-safe reason_code and
        error_class, the configured annotators (sorted keys of the result's
        ``annotations`` block), the enforced action identity, and the evidence
        artefact plus sorted pointer keys. No raw payload is read.
        """

        verdict = result.verdict
        evidence = verdict.evidence
        artefact = evidence.artefact if evidence is not None else None
        pointer_keys = (
            tuple(sorted(evidence.verification_pointers))
            if evidence is not None
            else ()
        )
        return cls(
            event_type=TelemetryEventType.DECISION,
            intervention_point=intervention_point,
            decision=verdict.decision,
            reason_code=safe_reason_code(verdict.reason),
            error_class=error_class_for(verdict.reason),
            policy_id=policy_id,
            annotators=_annotator_names(result.policy_input),
            enforcement_mode=mode,
            duration_ms=duration_ms,
            evidence_artefact=artefact,
            evidence_verification_pointer_keys=pointer_keys,
            action_identity=result.action_identity,
            metadata={},
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize to a JSON-ready dict containing only redaction-safe fields.

        Enum members are flattened to their wire strings. The returned mapping
        is the complete telemetry surface; any field absent here is, by
        construction, withheld from sinks.
        """

        return {
            "event_type": self.event_type.value,
            "intervention_point": (
                self.intervention_point.value
                if isinstance(self.intervention_point, InterventionPoint)
                else self.intervention_point
            ),
            "decision": self.decision.value if self.decision is not None else None,
            "reason_code": self.reason_code,
            "error_class": self.error_class,
            "policy_id": self.policy_id,
            "annotators": list(self.annotators),
            "enforcement_mode": (
                self.enforcement_mode.value if self.enforcement_mode is not None else None
            ),
            "duration_ms": self.duration_ms,
            "evidence_artefact": self.evidence_artefact,
            "evidence_verification_pointer_keys": list(
                self.evidence_verification_pointer_keys
            ),
            "action_identity": self.action_identity,
            "metadata": dict(self.metadata),
        }


def _annotator_names(policy_input: JsonValue | None) -> tuple[str, ...]:
    """Return the sorted annotator names from a policy input, values withheld.

    The names are the keys of the policy input ``annotations`` block, which is
    the host-side image of the configured annotators for the intervention point
    (mirrors core/src/runtime.rs annotators_for). Only the keys are read, never
    the annotator output values.
    """

    if not isinstance(policy_input, Mapping):
        return ()
    annotations = policy_input.get("annotations")
    if not isinstance(annotations, Mapping):
        return ()
    return tuple(sorted(str(name) for name in annotations))


@runtime_checkable
class TelemetrySink(Protocol):
    """Pluggable host telemetry sink.

    Shape mirrors the agent_os GovernanceEventSink so a host can treat ACS
    telemetry and agent_os governance events through one interface. `emit` is
    called once per evaluation. `force_flush` and `shutdown` are lifecycle
    hooks a host calls on drain and teardown; both default to no-ops on the
    built-in sinks that need nothing flushed.
    """

    def emit(self, event: TelemetryEvent) -> None: ...

    def force_flush(self) -> None: ...

    def shutdown(self) -> None: ...


class InMemoryTelemetrySink:
    """Records every emitted event in order. For tests and local inspection."""

    def __init__(self) -> None:
        self.events: list[TelemetryEvent] = []

    def emit(self, event: TelemetryEvent) -> None:
        self.events.append(event)

    def force_flush(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def clear(self) -> None:
        self.events.clear()


class JsonStdoutTelemetrySink:
    """Writes one JSON object per line. The audit.jsonl use case, built in.

    Each event is serialized with `TelemetryEvent.to_dict`, so a stdout or file
    stream becomes a redaction-safe JSON Lines audit log without any host-side
    schema work.
    """

    def __init__(self, stream=None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def emit(self, event: TelemetryEvent) -> None:
        line = json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)
        self._stream.write(line + "\n")

    def force_flush(self) -> None:
        flush = getattr(self._stream, "flush", None)
        if callable(flush):
            flush()

    def shutdown(self) -> None:
        self.force_flush()


class MultiSink:
    """Fan-out wrapper that forwards each event to several sinks.

    A failure in one sink is logged and swallowed so it cannot starve the
    others or surface to the evaluation path. Telemetry is never load-bearing.
    """

    def __init__(self, sinks: Sequence[TelemetrySink]) -> None:
        self._sinks: tuple[TelemetrySink, ...] = tuple(sinks)

    @property
    def sinks(self) -> tuple[TelemetrySink, ...]:
        return self._sinks

    def emit(self, event: TelemetryEvent) -> None:
        for sink in self._sinks:
            try:
                sink.emit(event)
            except Exception:  # noqa: BLE001 - one sink must not break the others
                _LOGGER.warning(
                    "Telemetry sink %r raised in emit; event dropped for that sink.",
                    type(sink).__name__,
                    exc_info=True,
                )

    def force_flush(self) -> None:
        for sink in self._sinks:
            try:
                sink.force_flush()
            except Exception:  # noqa: BLE001 - flush is best effort
                _LOGGER.warning(
                    "Telemetry sink %r raised in force_flush.",
                    type(sink).__name__,
                    exc_info=True,
                )

    def shutdown(self) -> None:
        for sink in self._sinks:
            try:
                sink.shutdown()
            except Exception:  # noqa: BLE001 - shutdown is best effort
                _LOGGER.warning(
                    "Telemetry sink %r raised in shutdown.",
                    type(sink).__name__,
                    exc_info=True,
                )


def _otel_attributes(event: TelemetryEvent) -> dict[str, str]:
    """Build the OpenTelemetry metric attributes for an event.

    Mirrors integrations/otel/src/lib.rs metric_attributes. The action identity
    is intentionally omitted to keep metric cardinality bounded, matching the
    Rust bridge. Annotators and pointer keys are joined with commas exactly as
    the Rust mapping does.
    """

    attributes: dict[str, str] = {
        "event_type": event.event_type.value,
        "intervention_point": (
            event.intervention_point.value
            if isinstance(event.intervention_point, InterventionPoint)
            else str(event.intervention_point)
        ),
    }
    if event.enforcement_mode is not None:
        attributes["enforcement_mode"] = event.enforcement_mode.value
    if event.decision is not None:
        attributes["decision"] = event.decision.value
    if event.reason_code is not None:
        attributes["reason_code"] = event.reason_code
    if event.error_class is not None:
        attributes["error_class"] = event.error_class
    if event.policy_id is not None:
        attributes["policy_id"] = event.policy_id
    if event.annotators:
        attributes["annotators"] = ",".join(event.annotators)
    if event.evidence_artefact is not None:
        attributes["evidence_artefact"] = event.evidence_artefact
    if event.evidence_verification_pointer_keys:
        attributes["evidence_verification_pointer_keys"] = ",".join(
            event.evidence_verification_pointer_keys
        )
    return attributes


class OtelMetricsTelemetrySink:
    """OpenTelemetry metrics sink matching the Rust agent_control_specification_otel crate.

    Emits the per-decision counters ``acs_intervention_{allow,deny,warn,
    escalate,transform}_total`` and the duration histogram
    ``acs_intervention_duration_ms`` under the meter name
    ``agent_control_specification`` by default.

    `opentelemetry` is an optional dependency. It is imported lazily; when it is
    absent the sink degrades to a safe no-op after a single warning, so a host
    can wire it unconditionally without making OpenTelemetry a hard dependency.
    """

    def __init__(self, meter_name: str = DEFAULT_OTEL_METER_NAME, *, meter_provider: object | None = None) -> None:
        self.meter_name = meter_name
        self._available = False
        self._meter_provider = meter_provider
        self._decision_counters: dict[str, object] = {}
        self._duration_histogram: object | None = None
        try:
            from opentelemetry import metrics as otel_metrics
        except ImportError:
            warned_once = OtelMetricsTelemetrySink._import_warning_emitted
            if not warned_once:
                OtelMetricsTelemetrySink._import_warning_emitted = True
                _LOGGER.warning(
                    "opentelemetry is not installed; OtelMetricsTelemetrySink is a no-op. "
                    "Install the 'opentelemetry-api' package to export ACS metrics."
                )
            return
        # Default to the global meter provider so the sink matches the Rust
        # crate's global::meter_with_scope behavior. An explicit provider can be
        # injected for isolation or deterministic testing.
        if meter_provider is not None:
            meter = meter_provider.get_meter(meter_name)
        else:
            meter = otel_metrics.get_meter(meter_name)
        for decision in _DECISION_WIRE_STRINGS:
            self._decision_counters[decision] = meter.create_counter(
                f"acs_intervention_{decision}_total"
            )
        self._duration_histogram = meter.create_histogram(
            "acs_intervention_duration_ms"
        )
        self._available = True

    _import_warning_emitted: bool = False

    @property
    def available(self) -> bool:
        """True when opentelemetry was importable and instruments are live."""

        return self._available

    def emit(self, event: TelemetryEvent) -> None:
        if not self._available:
            return
        attributes = _otel_attributes(event)
        if event.decision is not None:
            counter = self._decision_counters.get(event.decision.value)
            if counter is not None:
                counter.add(1, attributes)
        if event.duration_ms is not None and self._duration_histogram is not None:
            self._duration_histogram.record(event.duration_ms, attributes)

    def force_flush(self) -> None:
        if not self._available:
            return
        provider = self._meter_provider
        if provider is None:
            try:
                from opentelemetry import metrics as otel_metrics
            except ImportError:
                return
            provider = otel_metrics.get_meter_provider()
        flush = getattr(provider, "force_flush", None)
        if callable(flush):
            flush()

    def shutdown(self) -> None:
        self.force_flush()


def _coerce_sink(sink: TelemetrySink | Sequence[TelemetrySink] | None) -> TelemetrySink | None:
    """Normalize a sink argument into a single sink or None.

    A sequence of sinks is wrapped in a `MultiSink`; a lone sink is returned as
    is; `None` stays `None` so the default path stays zero-behavior-change.
    """

    if sink is None:
        return None
    if isinstance(sink, (list, tuple)):
        return MultiSink(tuple(sink))
    return sink


__all__ = [
    "DEFAULT_OTEL_METER_NAME",
    "InMemoryTelemetrySink",
    "JsonStdoutTelemetrySink",
    "MultiSink",
    "OtelMetricsTelemetrySink",
    "TelemetryEvent",
    "TelemetryEventType",
    "TelemetrySink",
    "error_class_for",
    "safe_reason_code",
]
