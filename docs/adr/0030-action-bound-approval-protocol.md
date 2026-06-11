---
title: Action-Bound, Fail-Closed Approval Protocol
last_reviewed: 2026-06-11
owner: agt-maintainers
---

# ADR 0030: Use an action-bound, fail-closed approval protocol

- Status: proposed
- Date: 2026-06-11
- Related issue: [#2478](https://github.com/microsoft/agent-governance-toolkit/issues/2478)

## Context

AGT has several approval mechanisms, but they do not share one durable security
contract:

- Agent Mesh policy rules can return `require_approval`, and the `govern`
  wrapper supports callback, console, webhook, and fail-safe auto-reject
  handlers.
- Agent OS has separate escalation, MCP gateway, framework-adapter, stateless
  kernel, and intent-authorization approval paths.
- The Agent Mesh audit schema has additive `arguments_hash`, `approver_did`,
  `policy_version`, `issued_at`, and `completed_at` fields.

These mechanisms prove that the basic workflow is useful, but they leave
different answers to security-critical questions:

- What exact action did an approver authorize?
- Can parameters, target, policy, or approval-chain configuration change
  between review and execution?
- Is a callback-supplied approver name an authenticated identity?
- Can an approval be replayed for another request or after expiry?
- Does `require_approval` mean denied, pending, or allowed with delayed
  execution?
- How are multiple approval entries linked to the policy decision and final
  execution?
- What happens after process restart while a request is pending?

The current Agent Mesh webhook payload contains descriptive action fields but
no request identifier, action digest, policy version, chain version, or expiry.
Its response trusts an `approver` string supplied in the response body. The
callback timeout is measured after a synchronous callback returns, so it does
not interrupt a callback that blocks beyond the deadline. Agent OS escalation
also permits timeout auto-approval through configuration, which is unsuitable
for a governance boundary.

The audit assurance fields added in spec v1.0 are not part of that version's
canonical entry hash. They are useful metadata, but they cannot yet be treated
as tamper-evident authorization evidence by themselves.

Issue #2478 proposes human and LLM approval chains. Human approval is compatible
with AGT's deterministic policy boundary, but an authoritative LLM judge would
conflict with [ADR-0004](0004-keep-policy-evaluation-deterministic.md), which
keeps model inference out of enforcement-time allow-or-deny decisions. An LLM
recommendation is also not human oversight.

For high-risk AI systems where the EU AI Act applies, this protocol may support
record-keeping and human-oversight measures under Articles 12 and 14. It does
not by itself establish conformity or satisfy provider or deployer obligations.

## Decision

AGT will define one versioned, action-bound approval protocol. A
`require_approval` policy result is a suspended decision, not an allow decision
and not a deny decision with a special reason. Execution remains impossible
until the exact request receives a terminal approval resolution and the runtime
revalidates that resolution immediately before execution.

The reference schema and coordinator will live in the published Python
governance surface under `agent-governance-python/agent-mesh/`. Agent OS and
framework integrations will adapt their approval paths to the shared contract
rather than define new approval record formats.

### 1. Enforcement outcomes

The canonical enforcement outcomes are:

- `allow`: execution may proceed immediately.
- `deny`: execution must not proceed.
- `require_approval`: execution is suspended pending a terminal approval
  resolution.

Existing observational actions such as `warn`, `log`, and `audit` remain
available, but resolve to an allow or deny enforcement outcome with metadata.
They are not additional terminal authorization states.

For compatibility, a `PolicyDecision` carrying `require_approval` may retain
`allowed = false`, but consumers MUST inspect the explicit outcome and MUST NOT
collapse it into an ordinary denial.

### 2. Action binding

Before creating an approval request, the runtime constructs an `ActionBinding`
from the exact executable request:

```yaml
schema_version: "1.0"
operation: tool.invoke
agent_id: agent-123
subject_id: user-456
target:
  tool_name: sql_execute
  tool_schema_version: "2"
  resource: prod-db
parameters:
  statement: "UPDATE accounts SET status = ? WHERE id = ?"
  values: ["closed", 42]
```

`action_digest` is the lowercase hexadecimal SHA-256 digest of the RFC 8785
JCS serialization of this object. The full parameters do not need to be stored
in the approval record, but the execution boundary MUST be able to recompute
the digest from the action it is about to execute.

The binding includes the acting agent, represented subject, operation, target,
tool schema version, resource, and parameters. An approval for one binding
cannot authorize another.

### 3. Protocol objects

The protocol separates four objects.

#### Policy decision

```yaml
policy_decision_id: pd_01...
verdict: require_approval
action_digest: sha256:...
policy_rule_id: production-db-writes
policy_version: "2026.06.11"
approval_chain_id: high-risk-tools
approval_chain_version: "3"
decided_at: "2026-06-11T12:00:00Z"
```

#### Approval request

```yaml
approval_request_id: ar_01...
policy_decision_id: pd_01...
action_digest: sha256:...
agent_id: agent-123
subject_id: user-456
operation: tool.invoke
target_resource: prod-db
approval_chain_id: high-risk-tools
approval_chain_version: "3"
requested_at: "2026-06-11T12:00:01Z"
expires_at: "2026-06-11T12:10:01Z"
status: pending
fail_closed_on_timeout: true
```

#### Approval chain entry

```yaml
approval_request_id: ar_01...
chain_entry_id: ace_01...
stage_index: 0
approver_kind: human
approver_identity: "did:web:example.com:users:alice"
identity_assurance: oidc
decision: allow
reason_code: reviewed-production-change
decided_at: "2026-06-11T12:03:10Z"
input_digest: sha256:...
previous_entry_digest: null
entry_digest: sha256:...
```

`input_digest` covers the approval request fields presented to the approver.
`entry_digest` covers the complete chain entry except itself, using
SHA-256 over JCS. Entries are append-only and link through
`previous_entry_digest`.

#### Approval resolution

```yaml
approval_resolution_id: apr_01...
approval_request_id: ar_01...
outcome: allow
action_digest: sha256:...
policy_version: "2026.06.11"
approval_chain_version: "3"
final_entry_digest: sha256:...
resolved_at: "2026-06-11T12:03:11Z"
```

Only an `ApprovalResolution` with `outcome: allow` can release execution.
Individual allow votes are not execution tokens.

### 4. Chain semantics

Approval-chain configuration is versioned and immutable for the lifetime of a
request. The first implementation supports ordered stages with all required
stages satisfied:

- each stage declares permitted approver identities or roles;
- each approval entry is checked against the stage's identity requirements;
- a deny decision terminates the chain immediately;
- allow is terminal only after all required stages have allowed;
- duplicate submissions are idempotent by `chain_entry_id`;
- conflicting submissions for the same stage are rejected and audited;
- expiry, transport failure, invalid identity, invalid schema, or missing
  required response resolves to deny or expired, never allow.

Quorum, parallel voting, delegation, and break-glass approval are future
extensions and require explicit protocol fields. They must not be inferred
from repeated callback responses.

### 5. Identity and transport

Webhook is the first production transport, but webhook is not an approver
identity type. A webhook can connect AGT to a human workflow or deterministic
external approval service.

The webhook contract MUST:

- be schema-versioned;
- send `approval_request_id`, `policy_decision_id`, `action_digest`,
  `policy_version`, `approval_chain_version`, and expiry;
- authenticate the remote service;
- authenticate or carry a verifiable assertion for the approving principal;
- require the response to echo the request and action binding;
- reject body-supplied identity strings that are not bound to authenticated
  transport or a verified identity assertion;
- support idempotent retries;
- fail closed on timeout, authentication failure, malformed responses, and
  request-binding mismatch.

The coordinator persists pending requests outside process memory. Waiting for
human input does not hold an execution thread or rely on a synchronous callback
remaining alive. A worker may resume a request after restart by loading its
durable state.

### 6. Execution-time validation

Immediately before execution, the enforcement point atomically verifies:

1. the resolution exists and is terminal allow;
2. the request is not expired, cancelled, denied, or already consumed;
3. the current action digest equals the approved action digest;
4. the current policy version equals the approved policy version;
5. the configured chain version equals the approved chain version;
6. all required chain entries and identities are valid;
7. the approval has not already been consumed where one-time use is required.

Any mismatch denies execution and emits a reason code. The runtime creates a
new policy decision and approval request if the caller still wants to execute
the changed action.

For irreversible or externally visible actions, the approval MUST be consumed
in the same transaction or idempotency boundary that starts execution. This
prevents two workers from racing to reuse one approval.

### 7. Audit evidence

The runtime emits linked events for:

- `policy_decision`;
- `approval_requested`;
- `approval_chain_entry`;
- `approval_resolved`;
- `approval_expired` or `approval_cancelled`;
- `approval_consumed`;
- execution allowed or denied.

Events carry the policy decision ID, approval request ID, approval resolution
ID, action digest, policy version, chain version, and trace ID as applicable.
Agent Mesh `AuditEntry` assurance fields SHOULD be populated, but verifiers
MUST NOT claim those optional v1.0 fields are tamper-evident until the audit
specification's versioned canonical hash includes them.

The approval-entry hash chain is mandatory for the protocol. Detached Ed25519
signatures or externally anchored receipts are optional extensions. They may
strengthen non-repudiation but are not required for the first implementation.

### 8. LLM recommendations

An LLM may produce an advisory recommendation, explanation, or risk annotation
for a human reviewer. That output:

- cannot satisfy a human approval stage;
- cannot directly produce a terminal allow or deny resolution;
- is recorded separately from authenticated approval entries;
- must identify the model and prompt or configuration version when retained.

Making an LLM authoritative in the enforcement path requires a separate ADR
that explicitly revisits ADR-0004 and its determinism, availability, prompt
injection, and accountability consequences.

### 9. Migration

Implementation proceeds without a breaking flag day:

1. Add the versioned protocol models, digest helpers, durable store protocol,
   and approval coordinator to Agent Mesh.
2. Add `require_approval` to the Agent OS policy evaluator outcome model and
   adapt Agent OS escalation, MCP gateway, stateless kernel, intent
   authorization, and framework integrations to the coordinator.
3. Wrap existing `ApprovalHandler` callbacks as same-process compatibility
   adapters. They receive the new request object and create protocol entries
   internally.
4. Replace the existing webhook payload with the versioned binding contract,
   retaining the old payload only behind an explicit legacy adapter.
5. Deprecate timeout auto-approval and unverified body-supplied approver
   identity. Strict mode rejects both from its first release.
6. Track non-Python SDK parity in follow-up issues after the Python contract is
   accepted and tested.

The existing intent lifecycle may supply storage and optimistic-concurrency
patterns, but approval requests remain distinct from execution intents:
an intent describes a planned scope, while an approval authorizes one exact
action binding under one policy and chain version.

## Acceptance criteria

The first implementation is complete when tests prove:

- `require_approval` cannot execute without a terminal allow resolution;
- approval for digest A cannot execute digest B;
- changing target, parameters, policy version, or chain version invalidates
  the old approval;
- timeout, missing response, callback failure, restart, and malformed webhook
  response fail closed;
- unverified approver identity cannot satisfy a stage;
- a deny entry short-circuits the chain;
- an allow resolution is emitted only after all required stages pass;
- duplicate webhook deliveries are idempotent;
- one-time approval cannot be consumed twice under concurrency;
- audit events reconstruct the path from policy decision through approval to
  execution;
- LLM advisory output cannot create an approval resolution.

## Consequences

Approval becomes a durable authorization protocol rather than a boolean
callback. This closes parameter-swap, replay, stale-policy, unauthenticated
approver, restart, and timeout fail-open risks, and gives operators a
reconstructible evidence trail.

The tradeoffs are additional schema, storage, identity integration, and
execution latency. Existing lightweight callbacks remain available through a
compatibility adapter, but deployments seeking strong approval assurance must
configure durable storage and verified approver identity.

The decision also narrows #2478: the first delivery is the shared schema,
coordinator, and webhook-backed human approval path. LLM judging remains
advisory and is not part of the authoritative MVP.

## Alternatives considered

### Keep independent approval implementations

Rejected. The same security invariants would continue to be implemented
differently across Agent Mesh, Agent OS, MCP, and framework adapters.

### Treat `require_approval` as an ordinary deny

Rejected. It loses durable pending state and encourages callers to retry
without a request identity or binding.

### Trust callback response fields

Rejected. A self-asserted approver name does not prove who approved the action,
and an unbound boolean can be replayed for changed parameters.

### Require signed receipts in the MVP

Rejected. Verified transport identity plus the mandatory approval-entry hash
chain closes the immediate authorization gaps without introducing key
provisioning as a prerequisite. Signed receipts remain a compatible extension.

### Permit LLM judges to approve directly

Rejected for this ADR. It conflicts with the accepted deterministic enforcement
boundary and does not constitute human oversight.

## References

- [Issue #2478](https://github.com/microsoft/agent-governance-toolkit/issues/2478)
- [ADR-0004: Keep policy evaluation deterministic](0004-keep-policy-evaluation-deterministic.md)
- [ADR-0013: Fail closed on policy evaluation errors](0013-fail-closed-on-policy-evaluation-errors.md)
- [ADR-0017: Merkle chain for audit tamper evidence](0017-merkle-chain-for-audit-tamper-evidence.md)
- [ADR-0026: Azure Functions PDP behind AI Gateway](0026-foundry-ai-gateway-functions-pdp.md)
- [Audit and Compliance Specification 1.0](../specs/AUDIT-COMPLIANCE-1.0.md)
- [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [RFC 8785: JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785)
