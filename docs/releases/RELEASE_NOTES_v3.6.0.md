# Agent Governance Toolkit v3.6.0

**Release Date:** 2026-05-12

> [!IMPORTANT]
> **Public Preview** - All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA.

## Highlights

### Formal Specifications Published

v3.6.0 formalizes the governance architecture with six specification documents:

- **AgentMesh Identity and Trust** v1.0 - DID lifecycle, Ed25519 signatures, trust scoring
- **AgentMesh Trust and Coordination** v1.0 - handshake protocol, capability delegation
- **Agent Hypervisor Execution Control** v1.0 - privilege rings, resource quotas, isolation
- **Agent SRE Governance** v1.0 - SLOs, error budgets, anomaly detection
- **MCP Security Gateway** v1.0 - tool allowlists, PII scanning, SSRF prevention
- **Framework Adapter Contract** v1.0 - SPI for pluggable framework integration
- **Audit and Compliance** v1.0 - Merkle-chained logs, retention, evidence export

### Security Hardening Sprint

319 fixes including:
- Path traversal guards across SRE, signing, and spec modules
- SSRF blocklist expansion (.NET OPA backend, TypeScript Cedar)
- HMAC verification before nonce commit in MCP message signer
- Shell injection prevention in GitHub Actions inputs
- Rust prompt injection guard
- VectorClock causal ordering and fail-closed SessionIsolation
- YAML deserialization hardened to JSON_SCHEMA (TypeScript)

### Cross-Org Agent Federation (ADR-0007)

`ExternalJWKSProvider` enables agents from different organizations to verify each
other's identities via federated JWKS endpoints without sharing private keys.

### Governance Sidecar Container

Production-ready container image for sidecar deployment patterns. Includes the
full governance middleware stack, OTEL bootstrap, and Prometheus `/metrics` endpoint.

### Execution Ring Enforcement

Privilege rings (previously stubs) now enforce real isolation boundaries.
Agents cannot escalate beyond their assigned ring without explicit delegation.

### New Integrations

- **Azure ACA Sandbox Provider** - container-based sandboxing on Azure Container Apps
- **AWS Bedrock Agent Adapter** - governance wrapper for Bedrock Agents
- **RAG Governance** - retrieval access control with Cedar policies and LlamaIndex adapter
- **Agent Shield** - 5-stage guardrails engine (prompt defense, PII/CRI detection)
- **Copilot CLI Governance** - governance checks for Copilot CLI tool invocations
- **GitHub Actions Governance Gate** - block non-compliant agent deployments in CI/CD

### StdoutAuditSink and Execution Context

New audit sink for containerized deployments (Kubernetes, Docker, OpenShell) that
writes JSONL to stdout. Audit entries now carry execution-context fields
(`sandbox_id`, `environment`, `container_runtime`) when available.

## Added

- **6 formal specifications** - identity, trust, hypervisor, SRE, MCP security, adapters, audit (#2344, #2353, #2360, #2361, #2363, #2364, #2369, #2375)
- **ExternalJWKSProvider** for cross-org agent federation (#2380)
- **GovernanceEventSink SPI** for pluggable event routing (#2362)
- **Governance sidecar container** with OTEL and Prometheus (#2307, #2312)
- **Execution ring enforcement** beyond stubs (#2309)
- **Trust ceiling propagation** for delegated child agents (#2306)
- **ExternalPolicyBackend interface** for pluggable evaluators (#2304)
- **StdoutAuditSink** with execution-context enrichment (#2302, #2305)
- **Azure ACA sandbox provider** (#2236)
- **AWS Bedrock Agent adapter** (#1833)
- **RAG Governance** package with Cedar + LlamaIndex (#1754, #1820, #1975)
- **Agent Shield** 5-stage guardrails integration (#1805)
- **PII/CRI detection** in MCP Security Gateway (#1815)
- **Copilot CLI governance package** (#2272)
- **GitHub Actions governance gate** (#2102)
- **PluginInstaller** real artifact fetch with SHA-256 verification (#1980)
- **Attestation collector/verifier interfaces** (#2226)
- **Go quickstart example** (#1817)
- **.NET ASP.NET Core middleware example** (#1796)
- **Presentation demos** - 6 self-contained offline demo scripts (#2390)
- **dbt data quality evidence adapter** example (#2278)
- **ATR community import** example (#2308)
- **NOT_IN operator** for policy evaluation (#2373)
- **RFC process** and issue template (#2356)
- **License header enforcement** in CI (#2331)
- **Semantic PR title enforcement** (#2325)
- **25 retroactive ADRs** (0001-0025) documenting prior decisions (#2329, #2377)

## Fixed

- **StdoutAuditSink syntax error** from overlapping merge (#2382)
- **EU AI Act demo** Unicode encoding on Windows (#2388)
- **VectorClock** causal ordering and fail-closed SessionIsolation (#2346)
- **Path traversal** guards in SRE capture, signing, and specs (#2352)
- **HMAC verification** before nonce commit in MCP signer (#2354)
- **SSRF blocklist** expanded for cloud metadata endpoints (.NET) (#2358)
- **YAML deserialization** hardened to JSON_SCHEMA (TypeScript) (#2333, #2334)
- **Shell injection** prevention in Actions inputs (#2330)
- **Docker CLI args** - use ArgumentList instead of string concat (#2357)
- **PolicyAction validation** from YAML instead of unsafe cast (TS) (#2355)
- **Hypervisor isolation** tests aligned with fail-closed implementation (#2370)
- **CI hardening** - lint, safety check, docs deploy, ATR sync (#2341, #2345, #2348, #2349, #2365, #2367, #2371, #2376, #2378)
- **.NET streaming governance** for MAF agents (#2366)
- **AEGIS cleanup** consolidated tracker resolved (#2332)

## Changed

- **Tutorials reorganized** into collapsible customer-centric categories (#2389)
- **Repo structure simplified** with layout guide (#2391)
- **ADK wrap/unwrap/get_callbacks** deprecated with runtime warnings (#2359)
- **MeshClient** - event hooks, auto-reconnect, Ed25519 verify, heartbeat (#2090)
- **Golang examples gallery** covering every agentmesh module (#2275)

## Packages

| Package | Version |
|---------|---------|
| `agent-governance-toolkit` (meta) | 3.5.0 |
| `agent-os-kernel` | 3.6.0 |
| `agentmesh-platform` | 3.6.0 |
| `agentmesh-runtime` | 2.3.0 |
| `agent-sre` | 3.6.0 |
| `agent-compliance` | 3.6.0 |
| `agent-rag-governance` | 3.6.0 |
| `agent-hypervisor` | 3.6.0 |
| `agent-lightning` | 3.6.0 |
| `agentmesh-marketplace` | 3.6.0 |

## Upgrade Guide

```bash
pip install --upgrade agent-governance-toolkit[full]
agt doctor  # verify installation
agt verify  # confirm OWASP ASI 2026 compliance
```

No breaking changes from v3.5.0. New features are additive.
