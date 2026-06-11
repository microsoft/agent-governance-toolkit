# Observability

ACS core emits structured telemetry through a synchronous `TelemetrySink` trait. Core owns no exporter and starts no worker thread. Hosts that need async export wrap their own runtime handle inside the sink.

## Event model

`TelemetryEvent` carries a typed event kind plus ACS decision context. The common fields are intervention point, decision, reason code, error class, policy id, annotator names, enforcement mode, duration in milliseconds, action identity, and a small metadata map for stable extensions. Decision events are emitted once for every intervention point evaluation. Perf events use the same shape.

Known event kinds are `decision`, `annotator_dispatch`, `policy_evaluation`, `evaluation_timing`, `intervention_point.transformed`, `annotator_failed`, and `policy_failed`. The `intervention_point.transformed` event is added by AGT D2 and fires in addition to the base `decision` event when the verdict is `transform` per `spec/SPECIFICATION.md` §14. The upstream `effect_applied` event is removed by `spec/SPECIFICATION.md` §19 because effects are no longer part of the verdict surface.

Default telemetry is content redacted. Core does not place raw policy targets, subject text, tool arguments, model output, annotation payload values, or redaction replacement contents into event attributes. Safe defaults include stable ids, action identity hashes, names, modes, decisions, reason codes, error classes, durations, counts, lengths, and span counts. Policy reason text that is not shaped like a low cardinality code is reported as `policy_reason`.

The action identity is the `sha256:` digest over canonical policy input. It is safe for correlation because it does not reveal the underlying policy target, snapshot, annotation values, or projected tool data. It is high cardinality, so the OpenTelemetry metrics bridge does not attach it to counters or histograms.

Telemetry is fail safe. Core catches sink panics and never lets telemetry change the enforcement result.

## Provider seam

The core crate stays dependency light and does not depend on OpenTelemetry. The `agent_control_specification_otel` integration crate provides `OtelTelemetrySink`, which implements `TelemetrySink` with the `opentelemetry` crate. Instruments are built at construction. Emit performs attribute mapping, cached counter lookup, and histogram record only.

The OTel bridge emits counters named `acs_intervention_allow_total`, `acs_intervention_deny_total`, `acs_intervention_warn_total`, and `acs_intervention_escalate_total`. It records durations in `acs_intervention_duration_ms`.

## Perf telemetry knob

`PerfTelemetry` is a runtime level with wire values 0, 1, and 2. The default is 0.

| Wire | Level | Annotator dispatch and policy evaluation cost | Evaluation timing |
| --- | --- | --- | --- |
| 0 | Off | No | No |
| 1 | External | Yes | No |
| 2 | Full | Yes | Yes |

External events carry intervention point attribution plus annotator name or policy id. Failed external calls also carry the runtime reason. Full adds per evaluation timing in addition to the always emitted decision event.
