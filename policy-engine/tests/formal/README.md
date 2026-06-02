# ACS mediation formal model

This directory contains a Quint model for ACS stateless mediation.

The model covers one host supplied snapshot at one configured intervention point. It abstracts manifest validation, path resolution, annotation dispatch, policy dispatch, effect validation, policy output normalization, resource limits, and host approval routing into explicit inputs. Each run mediates one activity and reaches one terminal verdict.

The model intentionally excludes stateful concepts. It has no variables, resolvers, lifetimes, event bus, stateful sessions, or guard policy stages.

## Modeled behavior

- Verdicts are `allow`, `warn`, `deny`, and `escalate`.
- Reserved `runtime_error:*` reasons always produce `deny`.
- Effects are applied only in enforce mode and only for `allow` or `warn`.
- Effects are never applied for `deny`, `escalate`, or runtime errors.
- `escalate` routes to a configured approval path only when the path and outcome are recognized.
- `escalate` without a configured path, failed path, or unrecognized outcome becomes `deny`.
- `allow` exists only when policy returned an explicit allow decision.

## Invariants

| Invariant | Property |
|---|---|
| `RuntimeErrorsDeny` | Runtime failures fail closed and never fail open. |
| `NoEffectsOnDenyOrEscalate` | Deny and escalate verdicts never apply effects. |
| `EffectsOnlyOnAllowOrWarn` | Any applied effect implies an allow or warn verdict. |
| `EscalateWithoutValidApprovalDenies` | Escalation without a configured and recognized approval path denies. |
| `EscalateRequiresApprovalRouting` | A terminal escalate verdict implies successful approval routing. |
| `ExactlyOneVerdict` | Every terminal mediated activity has exactly one verdict. |
| `ExplicitAllowRequired` | There is no allow without an explicit allow decision. |

## Running

From the repository root.

```bash
quint typecheck tests/formal/acs_mediation.qnt
quint run tests/formal/acs_mediation.qnt --invariant RuntimeErrorsDeny --verbosity=0
quint run tests/formal/acs_mediation.qnt --invariants RuntimeErrorsDeny NoEffectsOnDenyOrEscalate EffectsOnlyOnAllowOrWarn EscalateWithoutValidApprovalDenies EscalateRequiresApprovalRouting ExactlyOneVerdict ExplicitAllowRequired --verbosity=0
```
