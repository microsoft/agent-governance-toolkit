# Security conformance

The security conformance gate is the runnable assertion set for ACS fail closed behavior. Run it with this command.

```bash
cargo test --test security_conformance
```

## Invariants

Fail closed reserved reasons. Every reserved `runtime_error:` value reachable through build and evaluate execution is exercised through `tests/conformance/fail_closed_error_parity.json`. The core test also enumerates the complete section 15 table and checks `RuntimeError::reason()` for all thirteen variants.

Error paths do not apply effects. Runtime errors return deny verdicts with empty effect lists and no transformed policy target. Invalid or forbidden policy effects fail closed before a transform is exposed.

Extends confinement and URL loading. File based manifest path extends are confined to the top level manifest directory. Escaping paths fail closed during manifest loading. HTTPS URL extends use bounded fetches with optional SHA-256 pins. Plain `http`, unsupported schemes, hash mismatches, cycles, and URL body limit breaches fail closed.

Annotator isolation. Annotator output is stored only under `annotations.<name>`. Attempts to shadow `snapshot`, `policy_target`, `tool`, or `intervention_point` stay confined under the annotation key. Oversized annotator output and reserved `runtime_error:` reasons fail closed with `runtime_error:annotation_failed`.

Resource limits. Snapshot size, policy input depth, annotator count, annotator output size, extends depth, and merged manifest size are covered. All breaches use `runtime_error:resource_limit_exceeded` except annotator output size, which uses `runtime_error:annotation_failed`.

Approval identity. Core evaluation exposes a stable action identity over canonical policy input. SDK approval replay tests enforce mutation rejection with `runtime_error:approval_action_mismatch`, while this gate verifies the core identity and reserved reason mapping.

Evaluate only mode. A would be deny is recorded as a deny verdict with decision telemetry in `evaluate_only` mode. The runtime does not produce a transformed policy target in this mode.
