# ACS logging style guide

This guide is normative for ACS telemetry and log emission. It mirrors the event model in `docs/observability.md` and the Rust surface in `core/src/telemetry.rs`. ACS telemetry is evaluate only. It records policy evaluation facts without changing enforcement behavior and without exposing protected content.

## Canonical source order

Contributors must treat `docs/observability.md` as the first source for telemetry semantics. The Rust `TelemetryEventType` enum is the runtime source for event names. The canonical block below is the review and test target for this guide.

## Canonical event vocabulary

<!-- acs telemetry vocabulary start -->
```json
{
  "schema_version": 1,
  "events": [
    {
      "name": "decision",
      "required_fields": [
        "event_type",
        "intervention_point",
        "decision",
        "enforcement_mode",
        "duration_ms"
      ],
      "optional_fields": [
        "reason_code",
        "error_class",
        "policy_id",
        "annotators",
        "action_identity"
      ],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "decision",
        "reason_code",
        "error_class",
        "policy_id",
        "annotators",
        "enforcement_mode",
        "duration_ms",
        "action_identity"
      ]
    },
    {
      "name": "annotator_dispatch",
      "required_fields": [
        "event_type",
        "intervention_point",
        "annotators",
        "duration_ms"
      ],
      "optional_fields": [
        "reason_code",
        "error_class"
      ],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "annotators",
        "reason_code",
        "error_class",
        "duration_ms"
      ]
    },
    {
      "name": "policy_evaluation",
      "required_fields": [
        "event_type",
        "intervention_point",
        "policy_id",
        "duration_ms",
        "metadata.policy_type"
      ],
      "optional_fields": [
        "reason_code",
        "error_class"
      ],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "policy_id",
        "reason_code",
        "error_class",
        "duration_ms",
        "metadata.policy_type"
      ]
    },
    {
      "name": "evaluation_timing",
      "required_fields": [
        "event_type",
        "intervention_point",
        "decision",
        "enforcement_mode",
        "duration_ms"
      ],
      "optional_fields": [
        "reason_code",
        "error_class",
        "policy_id",
        "action_identity"
      ],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "decision",
        "reason_code",
        "error_class",
        "policy_id",
        "enforcement_mode",
        "duration_ms",
        "action_identity"
      ]
    },
    {
      "name": "intervention_point.transformed",
      "required_fields": [
        "event_type",
        "intervention_point",
        "policy_id",
        "enforcement_mode",
        "decision",
        "duration_ms"
      ],
      "optional_fields": [
        "reason_code",
        "annotators",
        "evidence_artefact",
        "evidence_verification_pointer_keys"
      ],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "policy_id",
        "enforcement_mode",
        "decision",
        "duration_ms",
        "reason_code",
        "annotators",
        "evidence_artefact",
        "evidence_verification_pointer_keys"
      ]
    },
    {
      "name": "annotator_failed",
      "required_fields": [
        "event_type",
        "intervention_point",
        "annotators",
        "reason_code",
        "error_class"
      ],
      "optional_fields": [],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "annotators",
        "reason_code",
        "error_class"
      ]
    },
    {
      "name": "policy_failed",
      "required_fields": [
        "event_type",
        "intervention_point",
        "policy_id",
        "reason_code",
        "error_class",
        "metadata.policy_type"
      ],
      "optional_fields": [],
      "documented_attribute_keys": [
        "event_type",
        "intervention_point",
        "policy_id",
        "reason_code",
        "error_class",
        "metadata.policy_type"
      ]
    }
  ]
}
```
<!-- acs telemetry vocabulary end -->

## Naming rules

Event type wire values use lowercase snake case and must remain stable. Field names use lowercase snake case. Metadata keys use the same rule and are documented with the `metadata.` prefix. New names require updates to `docs/observability.md`, this guide, lint coverage, and canonical parity tests in the same change.

## Redaction rules

Telemetry must never include raw policy target values, snapshot input, snapshot output, model requests, model responses, messages, tool arguments, tool results, annotation payload values, redaction replacement text, secrets, or PII. Use stable identifiers, action identity hashes, names, modes, decisions, reason codes, error classes, durations, counts, lengths, and span counts. Free text policy reasons must be reported as `policy_reason` unless they are already shaped as low cardinality identifiers.

## Severity and level rules

Core telemetry events do not carry a severity field. The OTel integration maps events into counters and histograms. Host sinks may map denied or failed outcomes to their own logging levels, but they must not add payload fields or reinterpret telemetry as an enforcement decision.

## Contributor rules

Do not add ad hoc event type strings. Use `TelemetryEventType` and `TelemetryEvent`. Do not add metadata keys unless this guide and `docs/observability.md` document them. Keep telemetry sink failures isolated from enforcement. Keep examples and tests separate from production telemetry. Run `python3 scripts/lint_logging.py` before submitting telemetry changes.
