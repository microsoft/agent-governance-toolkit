<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AGT Conformance

Regulated buyers, auditors, and supply chain verifiers increasingly ask a single question before signing off on an agentic deployment: *can you prove the agent was governed?* An AGT conformance claim is how you answer that question — it asserts that your implementation correctly intercepts agent actions before execution, evaluates them against policy, enforces authorization decisions, and produces tamper-evident records that a third party can verify offline.

Conformance is verified by running the AGT spec conformance suite — nine test files, one per formal specification, each test annotated with the normative section it covers.

---

## Conformance at a Glance

| Level | Specs covered | Required for |
|---|---|---|
| **Baseline** | Policy Engine, Audit & Compliance | Any AGT conformance claim |
| **Standard** | + Identity & Trust, MCP Gateway, AgentMesh Wire, Framework Adapter | Enterprise deployments; MCP tool governance |
| **Advanced** | + Hypervisor Execution Control, Agent Lightning, Agent SRE | Regulated industries; hardware-attested proof |

---

## Conformance Levels

### Baseline — Policy Engine and Audit

The non-negotiable minimum. If these six requirements fail, no governance claim holds.

| # | Requirement | Specification | Normative rule |
|---|---|---|---|
| B-1 | Pre-execution interception | [Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §10 | Every tool call intercepted before execution; bypass paths forbidden |
| B-2 | Deterministic policy evaluation | [Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §7 | Same input, same policy → same decision; no probabilistic shortcuts |
| B-3 | Authorization decision set | [Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §6 | Exactly ALLOW / DENY / MODIFY / STEP\_UP / DEFER; no other values emitted |
| B-4 | Tamper-evident audit chain | [Audit & Compliance](specs/AUDIT-COMPLIANCE-1.0.md) §3 | Merkle-chained records; each entry hashes the previous; offline verifiable |
| B-5 | Fail closed | [Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §16 | Policy evaluation error → DENY, never ALLOW; exception must be logged |
| B-6 | Additive policy contract | [Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) §18 | Parent DENY rules immutable through merge; child cannot widen a deny |

**Conformance tests:** `agent-governance-python/agent-os/tests/test_spec_policy_engine_conformance.py` and `test_spec_audit_compliance_conformance.py`

---

### Standard — Identity, Trust, and MCP Governance

Adds cryptographic agent identity and tool-call governance — the layer regulated buyers require before connecting agents to production data sources.

All Baseline requirements, plus:

| # | Requirement | Specification | Normative rule |
|---|---|---|---|
| S-1 | Cryptographic agent identity | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §4 | Ed25519 `did:mesh:<fingerprint>` assigned; signing key never leaves the agent process |
| S-2 | Challenge-response handshake | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §6 | IATP handshake completes within 200 ms; challenge is single-use |
| S-3 | Delegation ceiling propagation | [AgentMesh Trust & Coordination](specs/AGENTMESH-TRUST-COORDINATION-1.0.md) §5 | Delegated agent's trust ceiling ≤ parent's; no upward grant possible |
| S-4 | MCP tool-call governance | [MCP Security Gateway](specs/MCP-SECURITY-GATEWAY-1.0.md) §3 | Policy applied to every MCP tool invocation; ungoverned tool paths forbidden |
| S-5 | Wire integrity | [AgentMesh Wire Protocol](specs/AGENTMESH-WIRE-1.0.md) §4 | Every message signed; replay detected via sequence monotonicity |
| S-6 | Framework adapter contract | [Framework Adapter Contract](specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) §3 | Adapter exposes `ToolCallInterceptor` interface; framework-specific paths wire through it |

**Conformance tests:** `test_spec_identity_trust_conformance.py`, `test_spec_mesh_trust_conformance.py`, `test_spec_mcp_gateway_conformance.py`, `test_spec_adapter_contract_conformance.py`

---

### Advanced — Execution Control and Hardware Attestation

Adds execution isolation, liveness proof, and hardware-rooted signing. Required for deployments where the regulator or counterparty cannot trust the operator.

All Standard requirements, plus:

| # | Requirement | Specification | Normative rule |
|---|---|---|---|
| A-1 | Execution ring enforcement | [Hypervisor Execution Control](specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) §3 | Four-ring privilege model; ring boundary crossings are gated and logged |
| A-2 | Liveness attestation in handshake | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §8 | Liveness proof included in every trust handshake; stale proofs rejected |
| A-3 | Hardware keystore | [AgentMesh Identity & Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) §9 | Signing key sealed in TEE (SEV-SNP, TDX, or TPM); software-only key rejected for this level |
| A-4 | Governance latency SLOs | [Agent SRE Governance](specs/AGENT-SRE-GOVERNANCE-1.0.md) §4 | Policy evaluation latency instrumented; SLO breaches trigger circuit breaker |
| A-5 | Fast-path integrity | [Agent Lightning Fast-Path](specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) §3 | Fast-path decisions cryptographically consistent with full-path; no policy bypass |

**Conformance tests:** `test_spec_hypervisor_conformance.py`, `test_spec_sre_conformance.py`, `test_spec_lightning_conformance.py`

---

## Running the Conformance Suite

The nine conformance test files live alongside their respective packages. Each test is annotated with the spec section it covers. No custom pytest markers required — run the files directly.

### Install

```bash
# Baseline
pip install -e "agent-governance-python/agent-governance-toolkit-core[dev]"

# Standard adds
pip install -e "agent-governance-python/agent-governance-toolkit-integrations[dev]"

# Advanced adds
pip install -e "agent-governance-python/agent-hypervisor[dev]"
pip install -e "agent-governance-python/agent-lightning[dev]"
pip install -e "agent-governance-python/agent-sre[dev]"
```

### Run by level

=== "Baseline"

    ```bash
    pytest \
      agent-governance-python/agent-os/tests/test_spec_policy_engine_conformance.py \
      agent-governance-python/agent-os/tests/test_spec_audit_compliance_conformance.py \
      -v
    ```

=== "Standard"

    ```bash
    pytest \
      agent-governance-python/agent-os/tests/test_spec_policy_engine_conformance.py \
      agent-governance-python/agent-os/tests/test_spec_audit_compliance_conformance.py \
      agent-governance-python/agent-mesh/tests/test_spec_identity_trust_conformance.py \
      agent-governance-python/agent-mesh/tests/test_spec_mesh_trust_conformance.py \
      agent-governance-python/agent-os/tests/test_spec_mcp_gateway_conformance.py \
      agent-governance-python/agent-os/tests/test_spec_adapter_contract_conformance.py \
      -v
    ```

=== "Advanced (full suite)"

    ```bash
    pytest \
      agent-governance-python/*/tests/test_spec_*_conformance.py \
      -v
    ```

### Run a single spec

```bash
# Just the Policy Engine
pytest agent-governance-python/agent-os/tests/test_spec_policy_engine_conformance.py -v

# Just MCP Gateway governance
pytest agent-governance-python/agent-os/tests/test_spec_mcp_gateway_conformance.py -v

# Just identity and trust
pytest agent-governance-python/agent-mesh/tests/test_spec_identity_trust_conformance.py -v
```

### What passing looks like

```
PASSED  test_spec_policy_engine_conformance.py::TestSection10::test_pre_execution_interception_mandatory
PASSED  test_spec_policy_engine_conformance.py::TestSection7::test_policy_evaluation_deterministic
PASSED  test_spec_audit_compliance_conformance.py::TestSection3::test_merkle_chain_tamper_evidence
...
```

Each test name includes its spec section. A failed test tells you exactly which normative requirement your implementation violates.

---

## Regulatory Alignment

Conformance levels map to regulatory obligations. The table below is indicative — your legal team determines what suffices for your jurisdiction.

| Regulation | Minimum level | What AGT conformance satisfies |
|---|---|---|
| **EU AI Act Art. 9** (risk management) | Baseline | Policy engine coverage of high-risk actions |
| **EU AI Act Art. 12** (tamper-evident logging) | Baseline | Merkle-chained audit chain (B-4) |
| **EU AI Act Art. 14** (human oversight) | Standard | STEP\_UP and DEFER decisions (B-3) wired to human approval flows |
| **DORA Art. 9** (ICT risk) | Standard | Audit chain + agent identity binding |
| **SOC 2 CC6.1 / CC6.6** | Standard | Identity binding, delegation chain, tool-call logs |
| **HIPAA** (minimum necessary) | Standard | MCP tool-call governance (S-4) with PHI-scoped policy |
| **FedRAMP High / IL-4+** | Advanced | Hardware keystore (A-3) + execution ring enforcement (A-1) |
| **EU AI Act + DORA with hardware proof** | Advanced + TRACE | Hardware-attested governance record for offline third-party verification |

Full regulatory crosswalk documentation is in the [Compliance](compliance/index.md) section.

---

## Claiming Conformance

To register as AGT-conformant:

1. Run the suite for your target level and confirm all tests pass.
2. Link a CI run or test artifact that is publicly accessible (or sharable with maintainers under NDA for proprietary deployments).
3. Open a PR adding your implementation to [ADOPTERS.md](ADOPTERS.md) with: organization, implementation name, conformance level, test evidence link, and a maintainer contact.

### Baseline and Standard claims

| Condition | Requirement |
|---|---|
| Test evidence | CI run or artifact showing all suite tests passing |
| Production or pilot | At least one deployment (evaluation counts) |
| Maintainer contact | Named individual reachable via GitHub |
| Security disclosure | Acknowledge [SECURITY.md](../SECURITY.md) responsible disclosure process |

### Advanced claims — additional requirements

| Condition | Requirement |
|---|---|
| Hardware evidence | TEE measurement (SEV-SNP measurement, TDX RTMR, or TPM PCR values) from a production or staging run |
| Audit log sample | Anonymized Merkle-chained audit log with at least one STEP\_UP or DEFER record |
| Key isolation proof | Attestation report or HSM certificate showing signing key never left hardware boundary |

---

## Conformant Implementations

### Microsoft reference implementations

| SDK | Level | Language | Conformance tests |
|---|---|---|---|
| [agent-governance-python](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python) | **Advanced** | Python | All 9 spec files |
| [agent-governance-typescript](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-typescript) | **Standard** | TypeScript | Policy Engine, Identity & Trust, MCP Gateway |
| [agent-governance-dotnet](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-dotnet) | **Standard** | .NET / C# | Policy Engine, Identity & Trust |
| [agent-governance-rust](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-rust) | **Baseline** | Rust | Policy Engine, Audit |
| [agent-governance-golang](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-golang) | **Baseline** | Go | Policy Engine, Audit |

### Community

| Organization | Implementation | Level |
|---|---|---|
| [Dayos](https://dayos.com) | Cedar-based tool-dispatch governance for Google ADK (production) | Standard |
| [Provedit](https://provedit.ai) | OTLP receiver re-signing AGT decisions into Merkle chain with per-tenant dashboards | Standard |
| [Nobulex](https://github.com/arian-gogani/nobulex) | Bilateral receipt primitive for tamper-evident audit trails | Baseline |
| [chamber](https://github.com/ianphil/chamber) | AGT governance workflows for agent execution policy enforcement | Baseline |

*See [ADOPTERS.md](ADOPTERS.md) for the full adopter list, including organizations in evaluation.*

Want your implementation listed? Follow the [claiming conformance](#claiming-conformance) steps above.

---

## Conformance and TRACE

Standard and Advanced conformance produce cryptographically signed audit records. TRACE takes this one step further: it binds the policy version, hardware measurement, and tool-call transcript into a single signed artifact that a third party — a regulator, counterparty, or auditor — can verify offline without trusting the operator.

```
AGT policy enforcement (conformant)
        ↓
cMCP gateway (TEE-enforced policy, hardware-attested)
        ↓
TRACE Trust Record (signed: model + policy + hardware measurement + transcript)
        ↓
SCITT transparency log (public, append-only anchor)
```

An Advanced AGT conformance claim combined with TRACE emission is what moves the answer to "can you prove it was governed?" from *we have logs* to *here is a signed artifact, verifiable offline, rooted in silicon*.

- [TRACE specification](https://github.com/agentrust-io/trace-spec) — the open attestation format
- [cMCP](https://github.com/agentrust-io/cmcp) — reference implementation of AGT policy enforcement inside a confidential TEE with TRACE claim emission
- [TRACE registry](https://github.com/agentrust-io/trace-registry) — public Merkle anchor log

---

## Versioning

This page documents AGT conformance **v1.0**, corresponding to the 1.0 release of each formal specification. Specification versions are pinned in each spec file header. Conformance claims should record the spec version used for verification.

When specifications advance to v2.0, existing v1.0 claims remain valid for the specs they covered. The conformance suite version is recorded in `agent-governance-python/agent-governance-toolkit-core/src/agent_os/conformance/version.py`.

---

## Related

- [TESTING\_GUIDE.md](TESTING_GUIDE.md) — how to use the test suite end-to-end
- [Integration Tiers](integration-tiers.md) — governance depth at Tier 0 (sidecar), Tier 1 (SDK), and Tier 2 (deep hooks)
- [CSA ATF Conformance Assessment](compliance/atf-conformance-assessment.md) — AGT's self-assessment against the CSA Agentic Trust Framework (25/25 requirements, Senior maturity)
- [Specifications](specs/) — the normative specs each requirement references
- [ADOPTERS.md](ADOPTERS.md) — full adopter registry
