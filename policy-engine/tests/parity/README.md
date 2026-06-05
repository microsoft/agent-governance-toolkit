# ACS parity fixtures

These fixtures are the shared cross SDK contract for canonical ACS behavior.

## Fixtures

| Fixture | Purpose | Source |
| --- | --- | --- |
| `telemetry_redaction_canonical.json` | Enumerates core telemetry event kinds, SDK enforcement boundary events, safe emitted attributes, and fields that must stay withheld. | `docs/observability.md`, `docs/stateless-runtime.md`, `spec/SPECIFICATION.md`, `core/src/telemetry.rs`, `core/src/runtime.rs` |
| `verdict_dispatch_canonical.json` | Defines policy verdict normalization and proves only `transform` applies a transformed target in enforce mode. | `core/src/verdict.rs` and the stateless runtime evaluation flow |
| `resource_limits_canonical.json` | Captures default runtime resource budgets. | `core/src/limits.rs` |
| `error_mapping_canonical.json` | Maps every `RuntimeError` variant to its reserved reason. | `core/src/error.rs` and specification section 15 |
| `drift-catalog.json` | Documents intended SDK differences so parity tests do not over assert facade details. | Current SDK public surfaces |
| `drift-catalog.schema.json` | Validates the drift catalog shape. | This parity workstream |

## Drift policy

The drift catalog is allow list documentation. It covers construction and naming differences only where wire values and enforcement results remain identical. New SDK differences should be added only when they are intentional, observable, and outside the security contract.
