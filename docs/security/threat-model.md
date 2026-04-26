# Agent Governance Toolkit Threat Model

This document summarizes the security threat model for the Agent Governance
Toolkit (AGT) using a STRIDE-oriented view of the main trust boundaries in the
system.

For the current OWASP Agentic Top 10 mapping across all 10 categories, see
[`agent-governance-python/agent-compliance/docs/OWASP-COMPLIANCE.md`](../agent-governance-python/agent-compliance/docs/OWASP-COMPLIANCE.md).

## Scope

This threat model focuses on the runtime governance layer described in the
repository README:

- **Agent OS**: deterministic policy enforcement, approvals, MCP governance,
  context and policy controls
- **AgentMesh**: identity, trust scoring, delegated trust, and inter-agent
  communication
- **Agent Runtime**: execution rings, kill switch, sandbox boundaries, and saga
  controls
- **Agent SRE**: circuit breakers, replay, error budgets, and cascade detection

## Trust Boundaries

### 1. Human -> Agent

Users, operators, or reviewers provide prompts, approvals, policies, and
configuration. This is the main entry point for prompt injection, social
engineering, and unsafe approvals.

### 2. Agent -> Agent

Agents exchange requests, credentials, handoff context, and trust assertions.
This boundary is vulnerable to spoofed identities, tampered trust signals, and
over-broad delegation.

### 3. Agent -> Tool

Agents call MCP tools, file operations, shell commands, APIs, plugins, and
external services. This is the highest-risk execution boundary because a
successful bypass can lead to code execution, data exfiltration, or destructive
side effects.

### 4. Agent -> Platform Control Plane

Agents and services interact with package registries, CI/CD, release pipelines,
audit systems, and deployment targets. This boundary matters for supply chain,
artifact provenance, and operational integrity.

## High-Level Data Flow

```text
Human / Operator
    |
    v
Agent OS policy + approval checks
    |
    +--> AgentMesh identity / trust validation
    |
    +--> Agent Runtime execution boundary
    |
    +--> Agent SRE monitoring / replay / rollback
    |
    v
Tools, plugins, APIs, storage, and external services
```

## Primary Attack Surfaces

| Surface | Example threats |
|---------|-----------------|
| Prompts, retrieved context, memory | prompt injection, poisoned context, hidden instructions |
| Agent identity and delegation | spoofing, replay, forged credentials, trust laundering |
| Tool calls and plugins | code execution, shell abuse, dangerous file writes, privilege escalation |
| Policies and config files | unsafe defaults, policy drift, malformed policy documents |
| Audit and observability | log tampering, trace gaps, incomplete attribution |
| CI/CD and package publishing | supply chain tampering, unsigned artifacts, metadata confusion |

## STRIDE Analysis

| STRIDE category | Example risk in AGT | Primary mitigations |
|-----------------|---------------------|---------------------|
| **Spoofing** | Malicious agent impersonates a trusted peer | AgentMesh Ed25519 identity, DID-style identities, challenge-response handshakes, trust scoring |
| **Tampering** | Policies, audit logs, or artifacts are altered in transit or at rest | Agent OS policy interception, signed attestations, Merkle/hash-chain audit trails, ESRP-oriented publishing controls |
| **Repudiation** | A user or agent denies having taken a high-risk action | Immutable audit trail, replay tooling, trust and approval metadata, SRE event correlation |
| **Information Disclosure** | Agent leaks secrets, PII, or internal context through tools or messages | Capability scoping, MCP governance, VFS-style access control, prompt/content sanitization, least-privilege runtime boundaries |
| **Denial of Service** | Cascading failures, expensive loops, or runaway agents | Agent SRE circuit breakers, error budgets, runtime kill switch, bounded execution rings, rate and token controls |
| **Elevation of Privilege** | Agent escapes its intended scope or performs unauthorized actions | Agent Runtime rings, Agent OS allow/deny rules, approval workflows, trust decay, constrained delegation |

## Threats and Mitigations by Package

### Agent OS

### Main threats

- Prompt injection or goal hijack causes unsafe tool execution
- Agents call tools outside their approved scope
- Policies are too weak, too broad, or bypassed through aliases or malformed
  requests
- Hidden context or memory poisons future decisions

### Mitigations

- Deterministic policy evaluation before action execution
- Capability allowlists / denylists and action interception
- Approval workflows for sensitive actions
- Prompt, tool-input, and context sanitization
- Read-only policy and context controls for critical data paths

### AgentMesh

### Main threats

- Untrusted agents spoof trusted ones
- Delegation chains become too broad or unverifiable
- Inter-agent messages are replayed, forged, or accepted without validation
- Supply chain metadata about models, tools, or registries becomes untrustworthy

### Mitigations

- Ed25519-backed identity and DID-style agent credentials
- Trust scoring, trust decay, and revocation
- Challenge-response handshake and signed trust attestations
- AI-BOM / provenance tracking for models, data, and packages

### Agent Runtime

### Main threats

- Tool execution leads to code execution or destructive side effects
- Long-running sessions escape intended isolation
- Compromised agents persist after unsafe behavior
- Multi-step workflows leave partial state after failure

### Mitigations

- Ring-based execution isolation
- Kill switch and termination controls
- Saga orchestration / compensation for partial failures
- Sandboxed runtime boundaries and auditable execution paths

### Agent SRE

### Main threats

- One compromised or degraded agent causes cascading failures elsewhere
- Operators lack enough telemetry to understand or contain incidents
- Slow drift or anomalous behavior goes unnoticed

### Mitigations

- Circuit breakers and rollout controls
- Error budgets and SLO-driven enforcement
- Replay debugging and event correlation
- Anomaly and cascade detection across agent fleets

## Threat-to-Control Mapping

| Threat | Agent OS | AgentMesh | Agent Runtime | Agent SRE |
|--------|----------|-----------|---------------|-----------|
| Prompt injection | Policy interception, approval gates | Trusted handoff context | Runtime containment | Replay + anomaly signals |
| Capability escalation | Policy rules, explicit denies | Scoped trust / delegation | Ring isolation | Detection of unusual call patterns |
| Identity spoofing | N/A | Signed identity + handshake | Runtime session binding | Cross-service correlation |
| Data exfiltration | MCP and policy controls | Trust-aware peer gating | Sandboxed execution | Alerting on unusual transfer patterns |
| Rogue behavior | Policy deny / approval | Trust decay and revocation | Kill switch | Error budgets + cascade detection |
| Supply chain compromise | Policy and config review | AI-BOM / provenance | Signed artifacts and controlled runtime | Operational change monitoring |

## Residual Risks

AGT reduces risk but does not eliminate it. The main residual risks are:

- Misconfigured policies that are syntactically valid but semantically too
  permissive
- Human approvers making unsafe decisions under time pressure
- External tools or plugins that behave unsafely inside their allowed scope
- Gaps between documented controls and the exact deployment posture of a given
  organization
- **Knowledge flow risks**: AGT governs tool calls but not the knowledge
  (documents, embeddings, context) that agents consume and propagate — see
  [Limitations §7](LIMITATIONS.md#7-knowledge-governance-gap)
- **Credential persistence**: AGT does not observe or revoke credentials agents
  hold across tasks within a session — accumulated permissions may exceed
  what the current task requires — see
  [Limitations §8](LIMITATIONS.md#8-credential-persistence-gap)
- **Physical AI scope**: AGT governs software agents, not physical actuators,
  hardware interlocks, or real-time control loops — see
  [Limitations §10](LIMITATIONS.md#10-physical-ai-and-embodied-agent-governance)
- **Streaming data**: AGT evaluates policies per-action, not continuously over
  data streams — data freshness and quality are not assured — see
  [Limitations §11](LIMITATIONS.md#11-streaming-data-and-real-time-assurance)
- **DID method inconsistency**: Python/.NET use `did:mesh:*` while TS/Rust/Go
  use `did:agentmesh:*` — cross-SDK policy rules must account for both — see
  [Limitations §12](LIMITATIONS.md#12-did-method-inconsistency-across-sdks)

## Configuration Bypass Vectors

Governance enforcement depends on correct initialization. These configuration
states can result in agents running without effective governance:

| Bypass Vector | Risk | Mitigation |
|---------------|------|------------|
| **No policies loaded** | Default action is `allow` — all actions pass ungoverned | Always load policy files; use `strict` mode in production |
| **Permissive mode in production** | `permissive` mode allows all actions by default | Reserve `permissive` mode for dev/test; enforce `strict` in deployment |
| **Tool aliasing** | Registering a tool under an unexpected name bypasses name-based policy rules | Use `strict` mode (deny-by-default) so unrecognized tools are blocked; use regex patterns in policy rules rather than exact tool names |
| **Import-only governance** | Importing the governance module without configuring policies creates false "governed" status | Use `agt doctor` and `agt audit` to verify effective enforcement state |

> *These vectors were identified in external red-team analysis by [Periculo](https://www.periculo.co.uk/cyber-security-blog/red-teaming-the-microsoft-agent-governance-toolkit-15-bypass-vectors).*

## Recommended Operational Practices

- Keep policy scope narrow and prefer deny-by-default for high-risk tools
- Require explicit approval for destructive, financial, or identity-sensitive
  actions
- Rotate credentials and revoke trust aggressively when behavior changes
- Treat release metadata, package publishing, and provenance as part of the
  runtime security boundary
- Use SRE telemetry and replay tooling to investigate suspicious agent actions
