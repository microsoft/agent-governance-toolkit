---
title: Native FIDES-compatible IFC layer
last_reviewed: 2026-07-02
owner: agt-maintainers
---

# ADR: Native FIDES-compatible information flow control layer

**Status:** accepted for Agent OS runtime enforcement, FIDES-compatible metadata interop, bounded quarantined reveals, explicit declassification and endorsement, and first AgentMesh distributed receipt proof for native agent-to-agent messages.

## Context

AGT already enforced tool and action policy, but it could not deterministically prove that content provenance and confidentiality followed later allowed actions. A workflow could read untrusted or confidential content and then call an otherwise allowed sink without the sink seeing the accumulated context.

The native IFC layer closes that scoped gap for governed Agent OS execution by adding first-class content labels, FIDES-compatible metadata parsing, label propagation, and sink enforcement. The design aligns with the Microsoft Agent Framework security guidance for FIDES metadata and the FIDES paper, [*Securing AI Agents with Information-Flow Control*](https://arxiv.org/abs/2505.23643), without importing those framework types into AGT core.

## Decision

AGT owns a native IFC model instead of taking a runtime dependency on Microsoft Agent Framework security types. The model is FIDES-compatible at the metadata boundary so Agent Framework adapters can interoperate, while core enforcement remains framework-independent.

| Requirement | AGT implementation |
| --- | --- |
| Integrity provenance | `IntegrityLabel.TRUSTED` / `IntegrityLabel.UNTRUSTED` in `agent_os.policies.information_flow` |
| Confidentiality lattice | Existing `DataClassification` reused by `InformationFlowLabel.confidentiality` |
| Accumulated workflow context | Existing `ContextEnvelope` plus additive `integrity` field |
| Strict unlabeled-source default | `default_unlabeled_source_label()` returns untrusted/top_secret |
| Trusted sink policy | Operator-owned `GovernancePolicy.information_flow.sinks` / mapping-shaped `sink_tools` entries define `InformationFlowSinkPolicy.accepts_untrusted` and `max_allowed_confidentiality` |
| Runtime gate | `BaseIntegration.pre_execute_check(...)` denies incompatible sink flows before execution |
| Runtime propagation | `BaseIntegration.post_execute_check(...)` folds result labels into `ExecutionContext.context_envelope` |
| Structured denial | `ViolationCategory.INFORMATION_FLOW` and `deny_information_flow(...)` |
| FIDES adapter boundary | `normalize_fides_additional_properties(...)` converts Agent Framework/FIDES `additional_properties` into native AGT IFC metadata |
| Quarantined variable store | `QuarantinedInformationFlowStore` hides labeled tool results behind opaque `ifcvar://...` handles |
| Bounded reveal | `InformationFlowRevealPolicy` requires explicit authority, reason, bounded fields/capacity, and trusted authorizer approval before label release |
| Declassification and endorsement | `declassify_label(...)` and `endorse_label(...)` require explicit audited authority, reason, authorization reference, and trusted authorizer approval |
| ACS profile | `acs_information_flow_annotation(...)` emits `annotations.information_flow` without changing the ACS wire schema |
| Distributed message evidence | `InformationFlowReceipt` signs envelope reference, sensitivity, integrity, recipient, message subject, payload hash, timestamp, and nonce |

## Metadata contract

Source adapters can attach AGT or FIDES-compatible metadata under `information_flow`, `ifc`, `agt_ifc`, `fides`, or `additional_properties`. Runtime result accumulation trusts the adapter-owned metadata channel (`ToolCallResult.metadata` or equivalent object metadata); arbitrary fields inside model/tool result bodies are treated as content and do not self-label the output.

```python
{
    "information_flow": {
        "integrity": "untrusted",
        "confidentiality": "private",
        "categories": ["pii"],
        "source": "email",
    }
}
```

Sink capacity is trusted policy, not model-controlled request data. Configure sink policy on `GovernancePolicy.information_flow.sinks` or mapping-shaped `sink_tools` entries:

```python
{
    "information_flow": {
        "enabled": True,
        "strict": True,
        "sinks": {
            "send_email": {
                "accepts_untrusted": False,
                "max_allowed_confidentiality": "internal",
            }
        },
    }
}
```

In strict mode, governed sink calls are identified either by policy-configured
`information_flow.sink_tools` or by explicit `information_flow.role = "sink"`.
Calls marked as sources or transforms can run without sink capacity metadata.
Configured or marked sinks must have trusted policy-configured sink capacity and
fail closed when that policy is missing or malformed. Request payload metadata is
advisory for role identification only and cannot loosen sink policy.

Agent Framework/FIDES style `additional_properties.content_label` is normalized into the same native metadata:

```python
{
    "additional_properties": {
        "content_label": {
            "integrity": "untrusted",
            "confidentiality": "private",
            "labels": ["pii"],
            "source": "agent_framework_tool",
        }
    }
}
```

ACS hosts can carry the same profile under `annotations.information_flow`:

```json
{
  "annotations": {
    "information_flow": {
      "schema": "agt.ifc.annotation.v1",
      "context": {
        "aggregate_sensitivity": "confidential",
        "integrity": "untrusted"
      },
      "sink": {
        "accepts_untrusted": false,
        "max_allowed_confidentiality": "internal"
      }
    }
  }
}
```

## Security properties proven in this slice

- Untrusted integrity is sticky once folded into a `ContextEnvelope`.
- Confidentiality uses the existing max-lattice and never lowers during accumulation.
- Strict unlabeled outputs default to untrusted/top_secret, not public.
- A trusted-only sink denies accumulated untrusted context.
- A sink with policy-configured `max_allowed_confidentiality` denies over-confidential context.
- Malformed IFC metadata, such as unknown integrity labels or non-boolean sink
  fields, fails closed instead of silently downgrading protection.
- Runtime behavior is additive: IFC is disabled unless `GovernancePolicy.information_flow.enabled` is true.
- Audit events record redacted IFC state (`aggregate_sensitivity`, `integrity`, and label count), not raw envelope contents.
- FIDES-compatible `additional_properties` normalize to the native AGT label model at trusted adapter/source boundaries; sink capacity remains trusted operator policy.
- Quarantined variables hide raw untrusted tool content behind opaque handles until a bounded reveal policy permits a specific release. The built-in store is bounded and thread-safe, but it is an in-memory primitive for runtime integration rather than durable long-term storage.
- Declassification and endorsement are explicit transforms with authority, authorization reference, reason, trusted authorizer approval, and audit metadata. Labels do not decay automatically.
- A malicious untrusted customer message attempting to exfiltrate private content is blocked before an external email sink executes.

## Distributed AgentMesh receipt proof

AgentMesh relays may route opaque payloads, including encrypted payloads, without
inspecting their contents. Distributed IFC therefore travels as a signed receipt
on the native message frame:

```python
{
    "id": "message-001",
    "to": "did:mesh:receiver",
    "payload": {"task": "summarize"},
    "information_flow_receipt": {
        "schema_version": "agt.ifc.receipt.v1",
        "issuer_did": "did:mesh:sender",
        "recipient_did": "did:mesh:receiver",
        "subject_id": "message-001",
        "envelope_id": "env-support-001",
        "aggregate_sensitivity": "confidential",
        "integrity": "untrusted",
        "message_hash": "...",
        "nonce": "...",
        "signature": "...",
    },
}
```

The receiver verifies the sender identity signature, payload hash, recipient DID,
subject/message ID, expiration, replay nonce cache, workflow continuity, and
parent receipt monotonicity before treating the receipt as local IFC context.
Child receipts cannot lower aggregate sensitivity or restore `untrusted`
integrity to `trusted`.

## Proof in the repository

| Proof | Location |
| --- | --- |
| Native IFC model and metadata parsing | `agent-governance-python/agent-os/src/agent_os/policies/information_flow.py` |
| Runtime context, pre-execution check, post-execution check | `agent-governance-python/agent-os/src/agent_os/integrations/base.py` |
| Structured policy denial | `agent-governance-python/agent-os/src/agent_os/policies/decision.py` and `decision_factory.py` |
| Unit tests for label parsing and sink decisions | `agent-governance-python/agent-os/tests/policies/test_information_flow.py` |
| Runtime regression tests | `agent-governance-python/agent-os/tests/test_integrations.py` |
| Deterministic example | `examples/information-flow-control/` |
| ACS IFC annotation fixture | `policy-engine/core/tests/fixtures/policy-inputs/pre-tool-call-ifc-annotation.json` |
| AgentMesh signed receipt model | `agent-governance-python/agent-mesh/src/agentmesh/transport/information_flow.py` |
| AgentMesh receipt tests | `agent-governance-python/agent-mesh/tests/test_information_flow_receipts.py` |
| Distributed receipt example | `examples/distributed-information-flow-control/` |

## Boundaries for the IFC claim

The Agent OS runtime pieces above are enough for AGT to claim a native IFC layer
for governed local execution: labels are parsed, propagated, accumulated, and
enforced before configured sinks execute. The AgentMesh receipt work is a first
distributed proof for native agent-to-agent messages, not a full distributed
policy system. The signed receipt protects a native AgentMesh message handoff,
payload binding, downgrade checks, workflow continuity, and replay nonce checks.
Durable cross-session nonce storage, remote envelope resolution, relay-side
policy decisions, and end-to-end encrypted payload lifecycle semantics are not
required for the local IFC claim, but are required before AGT can claim broad
distributed IFC across arbitrary mesh topologies.

The current layer also does not infer labels from arbitrary natural language. Operators must label sources, rely on secure strict-mode defaults, or provide a separate classifier at ingress.

## References

- [Microsoft Agent Framework security guidance](https://learn.microsoft.com/en-us/agent-framework/agents/security?pivots=programming-language-python)
- [FIDES paper: *Securing AI Agents with Information-Flow Control*](https://arxiv.org/abs/2505.23643) ([PDF](https://arxiv.org/pdf/2505.23643))
