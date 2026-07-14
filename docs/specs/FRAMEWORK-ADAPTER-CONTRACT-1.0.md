---
title: Framework Adapter Contract
last_reviewed: 2026-07-11
owner: agt-maintainers
---

# Framework Adapter Contract

Framework adapters accept a native runtime and mediate supported lifecycle
events through `AdapterRuntimeSession`.

Adapters declare required intervention points, apply transforms before side
effects or disclosure, surface native `PolicyEvaluation` errors, and keep
session counters outside the stateless runtime. Approval resolution belongs to
the runtime.

See [Agent Control Specification](../../policy-engine/spec/SPECIFICATION.md)
and [v4 policy-language removal](../v4-removal.md).
