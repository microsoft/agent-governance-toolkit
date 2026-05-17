# ADR-0003: Cryptographic Delegation Chains

## Status

Accepted

## Context

In multi-agent orchestration, an orchestrator agent delegates tasks to sub-agents, which may delegate further. Without a formal delegation mechanism:

- Sub-agents cannot verify that instructions came from a legitimate principal
- Scope creep is undetectable (a sub-agent may exceed its delegated capabilities)
- Post-hoc audits cannot reconstruct the chain of authorization
- Prompt injection attacks can masquerade as legitimate delegations

The delegation system must maintain a verifiable chain from human authorization to terminal tool execution.

## Decision

Implement cryptographic delegation chains where each delegation hop produces a signed token containing:

- **Issuer**: The delegating agent's DID
- **Subject**: The receiving agent's DID
- **Granted capabilities**: Explicit list of allowed actions
- **Denied capabilities**: Explicit list of blocked actions (scope reduction)
- **Expiry**: Time-bound delegation
- **Context**: Task ID, human principal DID, human authorization timestamp

Each token is signed with the issuer's Ed25519 private key. The receiving agent verifies the signature against the issuer's public key (from the identity registry) before accepting any instruction.

Scope inheritance is strictly reductive: a sub-agent cannot grant capabilities it does not possess.

## Consequences

- **Easier**: Full chain-of-custody from human to tool call, prompt injection detection (injected instructions lack valid signatures), scope enforcement at every hop, clean audit trail
- **Harder**: Token overhead at each delegation boundary. Agents must have access to the identity registry for verification. Clock skew between agents can cause spurious expiry rejections (mitigated by configurable clock tolerance).

## References

- `agent-governance-python/agent-mesh/src/agentmesh/delegation/`
- Blog post: "Post-Hoc Accountability for Autonomous Agents" (Part 3)
