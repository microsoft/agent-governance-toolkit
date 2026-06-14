<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AGT Conformance

**Claim that your implementation correctly enforces the Agent Governance Toolkit specifications.**

An AGT-conformant implementation correctly intercepts agent actions, evaluates them against policy, enforces authorization decisions, and produces tamper-evident audit records. Conformance is verified by running the AGT conformance test suite (992 tests across all specifications) against your implementation.

---

## Conformance Levels

### Baseline — Core Policy Enforcement

The minimum bar. Covers the Policy Engine and audit chain.

| Requirement | Specification | What it means |
|---|---|---|
| **B-1 Pre-execution interception** | [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §10 | Every tool call is intercepted before execution |
| **B-2 Policy evaluation** | [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §7 | Rules evaluated deterministically; deny-on-error |
| **B-3 Authorization decisions** | [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §6 | ALLOW / DENY / MODIFY / STEP_UP / DEFER emitted |
| **B-4 Tamper-evident audit** | [Audit & Compliance](specs/AUDIT-COMPLIANCE-1.0.md) §3 | Merkle-chained audit records; offline verifiable |
| **B-5 Fail closed** | [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §16 | Policy evaluation errors result in DENY, not ALLOW |
| **B-6 Policy composability** | [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §18 | Parent DENY rules survive merge; additive contract |

### Standard — Identity and Trust

Adds cryptographic agent identity and cross-organization trust.

All Baseline requirements, plus:

| Requirement | Specification | What it means |
|---|---|---|
| **S-1 Cryptographic agent identity** | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §4 | Ed25519 DID assigned; signing key never leaves agent |
| **S-2 Challenge-response handshake** | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §6 | IATP handshake completes within 200 ms |
| **S-3 Delegation chain enforcement** | [AgentMesh Trust & Coordination](specs/AGENTMESH-TRUST-COORDINATION-1.0.md) §5 | Trust ceiling propagation; delegated agent cannot exceed parent |
| **S-4 MCP tool-call governance** | [MCP Security Gateway](specs/MCP-SECURITY-GATEWAY-1.0.md) §3 | Policy applied to every MCP tool invocation |
| **S-5 Wire protocol integrity** | [AgentMesh Wire Protocol](specs/AGENTMESH-WIRE-1.0.md) §4 | Messages signed; replay protection enforced |

### Advanced — Execution Control and Attestation

Adds hardware-backed enforcement and execution isolation.

All Standard requirements, plus:

| Requirement | Specification | What it means |
|---|---|---|
| **A-1 Execution ring enforcement** | [Agent Hypervisor Execution Control](specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) §3 | Four-ring privilege model; ring boundaries enforced |
| **A-2 Liveness attestation** | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §8 | Liveness proof included in every trust handshake |
| **A-3 Hardware keystore** | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §9 | Signing key sealed in TEE (SEV-SNP, TDX, or TPM) |
| **A-4 SLO enforcement** | [Agent SRE Governance](specs/AGENT-SRE-GOVERNANCE-1.0.md) §4 | Governance latency SLOs instrumented and enforced |
| **A-5 TRACE claim emission** | External: [TRACE spec](https://github.com/agentrust-io/trace-spec) | Hardware-attested governance record produced per session |

---

## Running the Conformance Suite

The conformance test suite is included in the repository. It runs against your implementation via the [Framework Adapter Contract](specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md).

### Prerequisites

```bash
pip install -e "agent-governance-python/agent-governance-toolkit-core[dev]"
pip install -e "agent-governance-python/agent-governance-toolkit-integrations"
```

### Run all conformance tests

```bash
pytest tests/ -m conformance -v
```

### Run by level

```bash
# Baseline only
pytest tests/ -m "conformance and baseline" -v

# Standard (includes Baseline)
pytest tests/ -m "conformance and (baseline or standard)" -v

# Full Advanced suite
pytest tests/ -m "conformance" -v
```

### Run against a specific spec

```bash
# Policy Engine spec conformance
pytest tests/ -m "conformance and policy_engine" -v

# MCP Security Gateway spec conformance
pytest tests/ -m "conformance and mcp_gateway" -v

# AgentMesh identity conformance
pytest tests/ -m "conformance and agentmesh_identity" -v
```

### Expected output

A conformant implementation produces:

```
========================= conformance results =========================
PASSED  tests/conformance/test_b1_pre_execution_interception.py
PASSED  tests/conformance/test_b2_policy_evaluation.py
...
========================= 992 passed in 4.3s ==========================
```

All 992 tests must pass for the corresponding conformance level claim to be valid.

---

## Claiming Conformance

To register your implementation as AGT-conformant:

1. **Run the full suite** against your implementation and confirm all tests for your target level pass.
2. **Open a PR** adding your implementation to [ADOPTERS.md](ADOPTERS.md) with the conformance level, test run evidence (CI link or artifact), and a contact.
3. **Meet the community conditions** below.

### Community conditions

| Condition | Requirement |
|---|---|
| Production deployment | At least one production deployment with active users |
| Open test evidence | CI run or test artifact publicly linkable |
| Maintainer contact | Named maintainer reachable via GitHub |
| Security disclosure | Committed to responsible disclosure via [SECURITY.md](../SECURITY.md) |

Advanced-level claims additionally require:

| Condition | Requirement |
|---|---|
| Hardware evidence | TEE measurement or TPM PCR values from a production run |
| Audit log sample | Anonymized Merkle-chained audit log demonstrating tamper-evidence |

---

## Conformant Implementations

| Implementation | Level | Language | Maintained by |
|---|---|---|---|
| [agent-governance-python](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python) | Advanced | Python | Microsoft |
| [agent-governance-typescript](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-typescript) | Standard | TypeScript | Microsoft |
| [agent-governance-dotnet](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-dotnet) | Standard | .NET / C# | Microsoft |
| [agent-governance-rust](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-rust) | Baseline | Rust | Microsoft |
| [agent-governance-golang](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-golang) | Baseline | Go | Microsoft |

*Want to list your implementation? Follow the [claiming conformance](#claiming-conformance) steps above.*

---

## Conformance and TRACE

Advanced conformance claims pair naturally with [TRACE](https://github.com/agentrust-io/trace-spec) — the hardware-attested governance record format. A conformant Advanced implementation can produce a TRACE Trust Record proving that policy was enforced in a verified hardware environment, giving auditors and counterparties offline-verifiable proof of governance without trusting the operator.

See [cMCP](https://github.com/agentrust-io/cmcp) for a reference implementation of AGT policy enforcement inside a confidential TEE with TRACE claim emission.

---

## Related

- [Testing Guide](TESTING_GUIDE.md) — how to use the test suite end-to-end
- [CSA ATF Conformance Assessment](compliance/atf-conformance-assessment.md) — AGT's self-assessment against the CSA Agentic Trust Framework
- [Specifications](specs/) — the normative specs each conformance requirement references
- [ADOPTERS.md](ADOPTERS.md) — registered conformant implementations
