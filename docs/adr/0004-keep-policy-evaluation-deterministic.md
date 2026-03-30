# ADR 0004: Keep policy evaluation deterministic and out of LLM control loops

- Status: accepted
- Date: 2026-03-26

## Context

The toolkit's core claim is that it governs what agents do before execution.
Repository docs describe deterministic action interception, declarative policy
rules, and sub-millisecond policy evaluation. The comparison docs also note
that LLM-based guard systems introduce tens to hundreds of milliseconds of
latency and probabilistic behavior. For a control plane that must be testable,
auditable, and safe under failure, inline policy decisions cannot depend on
model mood, prompt quality, or external inference availability.

## Decision

Keep enforcement-time policy evaluation deterministic by using declarative
YAML/JSON rules and supported policy backends such as Rego and Cedar. Do not
place an LLM in the allow-or-deny decision loop for runtime governance.

## Consequences

Policy outcomes remain reproducible, explainable, and cheap enough to run
before every action. That supports reliable tests, audit trails, and strict
failure handling. The tradeoff is that nuanced open-text reasoning has to happen
outside the enforcement path, for example when humans draft policies or review
shadow-mode findings, rather than inside the final policy decision itself.
