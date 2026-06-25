"""Governed call that exports redaction-safe telemetry to pluggable sinks.

Runs a single governed `AgentControl.run()` over the native runtime with a
custom Python policy, then fans each evaluation's `TelemetryEvent` out to a
JSON Lines audit sink, an in-memory sink, and, when `opentelemetry` is
installed, an `OtelMetricsTelemetrySink` that emits the same
`acs_intervention_*` metrics as the Rust `agent_control_specification_otel`
crate. Run it with `python examples/real_packages/telemetry.py`.
"""

from __future__ import annotations

import asyncio

from agent_control_specification import (
    AgentControl,
    InMemoryTelemetrySink,
    JsonStdoutTelemetrySink,
    MultiSink,
    OtelMetricsTelemetrySink,
)

MANIFEST = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: telemetry-example
policies:
  example_policy:
    type: custom
    adapter: example
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: example_policy
  output:
    policy_target: $.output
    policy:
      id: example_policy
"""


class ExamplePolicy:
    """Allows input, warns on output. Real decisions, no network."""

    def evaluate(self, invocation):
        if invocation["input"]["intervention_point"] == "output":
            return {"decision": "warn", "reason": "review_recommended"}
        return {"decision": "allow"}


def build_sink() -> MultiSink:
    sinks = [JsonStdoutTelemetrySink(), InMemoryTelemetrySink()]
    otel = OtelMetricsTelemetrySink()
    if otel.available:
        # opentelemetry is installed; export the acs_intervention_* metrics too.
        sinks.append(otel)
    else:
        print("# opentelemetry not installed; OtelMetricsTelemetrySink is a no-op")
    return MultiSink(sinks)


async def main() -> None:
    sink = build_sink()
    control = AgentControl.from_native(MANIFEST, policy_dispatcher=ExamplePolicy(), telemetry_sink=sink)

    # One governed call emits two telemetry events, one per intervention point.
    result = await control.run({"text": "summarize the quarterly report"}, lambda value: {"summary": value})
    print(f"# run value {result.value}")

    in_memory = next(child for child in sink.sinks if isinstance(child, InMemoryTelemetrySink))
    print(f"# captured {len(in_memory.events)} events")
    for event in in_memory.events:
        point = event.intervention_point
        point_name = point.value if hasattr(point, "value") else point
        print(f"# {point_name} -> {event.decision.value} ({event.reason_code}) in {event.duration_ms:.3f} ms")

    sink.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
