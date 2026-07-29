---
title: Native Agent Policy Runtime
last_reviewed: 2026-07-11
owner: agt-maintainers
---

# Native Agent Policy Runtime

The former Agent OS policy contract is removed. Agent Governance Toolkit uses
the Agent Control Specification runtime under [`policy-engine/`](../../policy-engine/).

Author a native manifest, bind policies to intervention points, and construct
the language SDK `AgentControl` or Python `AgtRuntime`. The normative contract
is [`SPECIFICATION.md`](../../policy-engine/spec/SPECIFICATION.md).

Use `agt migrate v4-to-v5` once for an existing project. Runtime modules do not
load legacy governance files.
