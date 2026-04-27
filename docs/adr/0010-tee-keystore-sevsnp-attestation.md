# ADR 0010: Add TEE keystore with SEV-SNP attestation for agent identity

- Status: proposed
- Date: 2026-04-26

## Context

AgentMesh identity currently proves **who** an agent is through Ed25519 DIDs
and proves **what** it can do through capabilities, delegation, and policy. It
does not prove **where** the agent is running or whether the signing key used by
the agent is protected by the execution environment.

That leaves a material gap for sensitive agent workloads. If an agent's signing
key is stored on disk, injected through an environment variable, or mounted as a
software secret, a compromised host can yield a fully valid agent identity. The
attacker can sign handshakes and exercise delegated authority from an
unapproved environment, even if the cryptographic identity itself remains valid.

Existing ADRs address adjacent layers:

- ADR 0001 establishes Ed25519 as the agent identity primitive.
- ADR 0003 constrains the trust handshake to a 200ms budget.
- ADR 0005 addresses liveness attestation: whether an agent is alive now.
- ADR 0007 and ADR 0008 address cross-organization identity and policy
  federation.
- ADR 0009 aligns AGT's attestation vocabulary with RFC 9334 RATS.

This ADR addresses a different property: **execution-environment attestation
and key origin**. The relying party should be able to distinguish a locally
stored software key from a key that was released into, or generated inside, a
hardware-attested trusted execution environment (TEE).

The first implementation should focus on a TEE keystore plus AMD SEV-SNP
attestation. The design should remain cloud-agnostic at the abstraction layer,
while being optimized for Azure in the first provider implementation because
Azure provides deployed SEV-SNP confidential VMs, Microsoft Azure Attestation
(MAA), and Azure Key Vault Secure Key Release (AKV SKR).

Intel TDX, TPM/measured boot, Azure Confidential ACI, AWS Nitro, GCP
Confidential Space, and other environments are intentionally sequenced after
the SEV-SNP foundation.

## Decision

Add optional TEE-bound identity support to AgentMesh through three core
abstractions:

1. `TEEKeyStore`: obtains the agent signing key from a hardware-bound source.
2. `AttestationCollector`: collects platform evidence from the runtime
   environment.
3. `AttestationVerifier`: verifies evidence and returns structured attestation
   claims for the trust and policy layers.

The v1 implementation starts with AMD SEV-SNP on Azure:

- `SKRKeyStore` releases the agent's Ed25519 private key through Azure Key
  Vault Secure Key Release after MAA validates a SEV-SNP attestation report.
- `AzureSEVSNPCollector` collects SEV-SNP evidence through Azure-supported
  mechanisms such as IMDS or `/dev/sev-guest`.
- `MAAVerifier` validates the attestation report, extracts structured claims,
  and checks configured reference values.

The model defines three key-origin tiers:

| Key origin | Description | Trust implication |
|---|---|---|
| `skr` | Key is released by an attestation-aware KMS after the TEE passes policy | Preferred production path for Azure |
| `tee_generated` | Key is generated inside the TEE and attestation binds the public key hash to the environment | Strongest residency model, requires registration flow |
| `local` | Existing software key behavior | Backward-compatible fallback with no TEE trust elevation |

Attestation evidence must bind to the specific agent, handshake, and public key
using a canonical report-data hash:

```text
SHA-256(
  "agentmesh-attest-v1"
  || len(agent_did) || agent_did
  || len(challenge_id) || challenge_id
  || nonce
  || public_key_hash
)
```

> **Encoding note:** `||` denotes byte concatenation. Strings are UTF-8 encoded.
> Length prefixes are 2-byte big-endian unsigned integers. `public_key_hash` is
> the raw 32-byte SHA-256 digest of the agent's Ed25519 public key.

This prevents replay, relay, and key-swapping attacks. A verifier should reject
evidence that is stale, bound to a different DID, bound to a different nonce, or
bound to a different public key.

The design is additive:

- Agents without TEE support continue to use existing identity behavior.
- TEE claims are exposed as optional trust attributes, not required protocol
  fields for every deployment.
- Trust score changes are additive bonuses or penalties only. Existing trust
  tiers are not rebalanced.
- Policy can require `key_origin`, `key_bound_to_tee`, `confidential_level`, or
  `tcb_status` for sensitive actions.

The core package must not take hard dependencies on platform-specific TEE
libraries. Azure-specific collectors, verifiers, and SKR dependencies should
ship as optional extras with lazy imports and clear errors when unavailable.

## Scope and sequencing

### Phase 1: ADR and foundation

Define the data model and interfaces:

- `AttestationEvidence`
- `AttestationClaims`
- `ConfidentialLevel`
- `TEEKeyStore`
- `AttestationCollector`
- `AttestationVerifier`
- `SKRKeyStore`
- `AzureSEVSNPCollector`
- `MAAVerifier`
- `LocalKeyStore` fallback

This phase should be testable without confidential hardware by using mock
collectors, mock MAA responses, and mock SKR flows. Real SEV-SNP plus AKV SKR
tests should run separately in an Azure confidential VM environment.

### Phase 2: Trust and policy integration

Extend the trust layer to carry optional attestation evidence and verified
claims:

- `TrustHandshake` can request and verify attestation.
- Cache keys include attestation requirements and evidence freshness.
- `require_attestation` and `require_tee_bound_key` modes fail closed when
  configured.
- Risk scoring adds an environment bonus without changing the existing score
  formula.
- Trust policy gains environment-aware conditions.

### Phase 3: Provider expansion

After the SEV-SNP keystore and attestation path is accepted, add additional
providers incrementally:

- Intel TDX attestation collector and verifier path.
- TPM/measured boot collector for non-TEE integrity signals.
- Azure Confidential ACI support, including CCE workload policy measurements.
- Non-Azure TEE providers such as AWS Nitro and GCP Confidential Space.
- Optional EAT serialization work that builds on ADR 0009's RATS alignment.

## Non-goals

- Do not require all agents to run in a TEE.
- Do not replace Ed25519 DID identity, SPIFFE/SVID, Entra, or external JWKS
  federation.
- Do not treat liveness attestation as execution-environment attestation. ADR
  0005 covers liveness; this ADR covers key origin and runtime evidence.
- Do not rebalance existing trust score components or silently change existing
  trust tiers.
- Do not add TDX, TPM, C-ACI, Nitro, or Confidential Space in the first
  implementation PR.
- Do not make Azure services mandatory for the abstraction layer. Azure is the
  first optimized provider implementation, not the only supported model.

## Consequences

TEE-bound identity closes a high-value gap in AgentMesh: a relying party can
verify not only that an agent holds a valid signing key, but that the key was
released into, or generated inside, an attested execution environment. This is
especially valuable for agents handling PII, financial workflows, regulated
operations, cross-organization calls, or high-impact MCP tools.

The design gives operators a policy control point. Sensitive actions can require
hardware-bound keys and current TCB status, while lower-risk agents can continue
using local keys. This preserves backward compatibility and avoids turning TEE
support into a deployment prerequisite.

The tradeoff is operational complexity. SEV-SNP and TDX collectors are
platform-specific and may require Linux-only native dependencies. AKV SKR and
MAA add startup-time dependencies and require reference values to be maintained
as platforms update firmware, guest images, and workload policies. Production
deployments must avoid silent downgrade from a configured TEE requirement to a
local-key fallback.

The first implementation should therefore fail closed when attestation is
required, log explicit downgrade events, keep platform dependencies optional,
and separate cloud-agnostic interfaces from Azure-specific provider code.
