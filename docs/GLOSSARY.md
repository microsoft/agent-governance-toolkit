# Glossary

Technical terms used across the Agent Governance Toolkit, its specifications, and architecture decision records.

---

### A

* **Agent Identity**: A cryptographic identity (Ed25519 key pair) that uniquely identifies an agent. Every governance action is tied to a verified identity.
* **Agent OS**: The core governance runtime that hosts the policy engine, lifecycle management, and governance gate. All agent actions pass through Agent OS before execution.
* **AgentMesh**: The trust and coordination layer that handles agent discovery, routing, delegation, and inter-agent communication with cryptographic verification.
* **Audit Trail**: A tamper-evident log of all governance decisions. Each entry is hash-chained to its predecessor, making retroactive modification detectable.

### C

* **Circuit Breaker**: A fault-tolerance pattern that stops forwarding requests to a failing downstream service after a threshold of consecutive failures. Used in Agent SRE to prevent cascading failures across agent networks.
* **CloudEvents**: An open specification (CNCF) for describing event data in a common format. AGT uses CloudEvents as the envelope format for governance events emitted through the GovernanceEventSink.
* **Commitment Anchor**: A cryptographic hash published to an external ledger (append-only log or blockchain) that proves a set of governance decisions existed at a specific point in time.
* **Compliance Framework**: A structured set of regulatory or industry requirements (e.g., OWASP, NIST AI RMF, EU AI Act, SOC 2) that AGT maps governance controls against.
* **Conformance Test**: A test that verifies an implementation meets the requirements of a formal specification. Each AGT spec includes a conformance test suite using RFC 2119 keywords.

### D

* **Decision BOM (Bill of Materials)**: A structured record attached to every policy decision that captures the inputs, rules evaluated, and outcome. Enables full reproducibility of any governance verdict.
* **Delegation Chain**: An ordered sequence of trust delegations from one agent to another. Each link in the chain is signed, and the chain is validated end-to-end before granting delegated permissions.
* **Delta Engine**: A component in Agent Hypervisor that computes minimal diffs between consecutive governance states, enabling efficient replication and audit without transmitting full snapshots.
* **Deterministic Policy Enforcement**: A system that ensures rules are applied exactly as written, with no ambiguity. If a rule says "No Shell Access", the system blocks it every single time.

### E

* **Execution Ring**: One of four privilege levels (Ring 0 through Ring 3) in Agent Runtime that controls what resources and operations an agent can access. Ring 0 is most privileged (system-level), Ring 3 is least privileged (sandboxed).
* **Execution Sandboxing**: A security mechanism for isolating running agents. Creates a constrained environment where an agent can operate without affecting other agents or the host system.

### F

* **Fail-Closed**: A design principle where the system denies the action when the policy engine cannot reach a decision (timeout, error, missing policy). The opposite of fail-open, which would allow the action by default.
* **Framework Adapter**: A thin integration layer that connects a third-party agent framework (LangChain, CrewAI, AutoGen, etc.) to AGT's governance pipeline. Adapters implement the Framework Adapter Contract specification.

### G

* **Governance Event**: A structured record emitted when a policy decision occurs. Contains the decision outcome, policy references, agent identity, timestamp, and Decision BOM.
* **GovernanceEventSink**: A pluggable interface for routing governance events to external systems (OpenTelemetry, SIEM, databases, message queues). Follows the structural typing pattern defined in ADR-0025.
* **Governance Gate**: The synchronous checkpoint in Agent OS that intercepts every agent action, evaluates it against active policies, and returns allow/deny before the action executes.

### H

* **Hash Chain**: See *Merkle Chain*.

### I

* **IATP (Identity and Trust Protocol)**: A protocol for establishing and verifying agent identity across organizational boundaries. Used by AgentMesh for cross-domain trust federation.

### K

* **Kill Switch**: An Agent SRE mechanism that immediately halts a specific agent or group of agents. Can be triggered manually, by SLO violations, or by anomaly detection. Takes effect within the SLA-defined time window.

### M

* **Merkle Chain**: A data structure where each audit record contains a cryptographic hash of the previous record, forming a tamper-evident chain. If any record is modified, all subsequent hashes become invalid.
* **MCP (Model Context Protocol)**: An open protocol for connecting AI models to external tools and data sources. AGT's MCP Security Gateway adds governance controls (policy checks, trust verification, rate limiting) to MCP tool calls.
* **Middleware**: A software layer that sits between the AI agent and the tools it uses. Intercepts actions to check if they are allowed before execution proceeds.

### O

* **OpenTelemetry (OTel)**: An open observability framework for traces, metrics, and logs. AGT uses OTel as a primary backend for GovernanceEventSink, enabling governance telemetry to flow into existing observability infrastructure.

### P

* **Policy**: A declarative rule that defines what an agent is allowed or denied from doing. Policies specify target agents (by identity, role, or trust score), target actions, and conditions.
* **Policy Linting**: Static analysis of policy definitions to detect conflicts, unreachable rules, shadowed permissions, and logical errors before deployment.
* **Policy Merge**: The process of combining multiple policies from different sources (organization, team, agent-level) into a single effective policy set, with defined precedence rules.

### R

* **RL Training Governance**: Controls in Agent Lightning that apply governance to reinforcement learning training loops. Includes violation penalties, reward shaping constraints, and training checkpoint verification.
* **Rollback**: The process of reverting an agent or policy to a previously known-good state. Agent SRE automates rollback when post-deployment SLO checks fail.

### S

* **SLO (Service Level Objective)**: A target for agent reliability or performance (e.g., "policy evaluation latency under 50ms at p99"). Agent SRE monitors SLOs and triggers alerts or kill switches on violations.
* **Structural Typing**: A type compatibility approach where an object satisfies an interface if it has the required methods, regardless of explicit inheritance. Used for GovernanceEventSink to allow any compatible object to serve as a sink without inheriting a base class.

### T

* **Trust Ceiling**: The maximum trust score an agent can achieve, regardless of its behavior. Set by organizational policy to cap the privileges any single agent can accumulate.
* **Trust Score**: A dynamic rating (0-1000) assigned to an agent based on its behavior history, verification status, and organizational policies. Higher scores grant access to more sensitive operations.
* **Trust Scoring**: The process of computing and updating an agent's trust score based on governance events, compliance history, and peer attestations.

### Z

* **Zero-Trust Identity**: A security model where no agent is trusted by default. Every agent must prove its identity using cryptographic keys for every action, regardless of network location or prior history.

---

### OWASP Agentic Security Issues

* **Goal Hijacking (ASI-01)**: When an attacker tricks an AI agent into ignoring its original instructions to follow new, malicious ones.
* **Tool Misuse (ASI-02)**: When an agent uses a tool in a way that was not intended, potentially causing damage or data loss.
* **Privilege Escalation (ASI-03)**: When an agent gains access to resources or permissions beyond what its policies allow.
* **Exfiltration (ASI-06)**: The unauthorized transfer of sensitive data from within the system to an external location controlled by an attacker.
