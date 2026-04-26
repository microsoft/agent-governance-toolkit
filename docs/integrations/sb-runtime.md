# Integrating sb-runtime (a Veritas Acta receipt format implementation)

This guide documents deploying [sb-runtime](https://github.com/ScopeBlind/sb-runtime) as a Ring 2/3 governance backend inside the Agent Governance Toolkit. sb-runtime is one implementation of the Veritas Acta receipt format ([draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)); the longer-lived object is the receipt format itself, not the specific signer.

> **TL;DR.** The Veritas Acta receipt format is the portable artifact. Any signer that emits receipts in that format, and any verifier that reads them (reference: [`@veritasacta/verify`](https://github.com/VeritasActa/verify)), participates in the same evidence graph. sb-runtime is one such signer: a single Rust binary that bundles Cedar policy evaluation, optional Landlock + seccomp sandboxing (Ring 3), and Ed25519-signed receipts. Operators already standardizing on [nono](https://github.com/always-further/nono) as the Linux sandbox primitive can compose the two: nono provides the sandbox layer, sb-runtime runs in `--ring 2` mode contributing only Cedar + receipt signing. The receipt produced is byte-identical either way.

---

## sb-runtime's role in the Veritas Acta receipt model

This guide focuses on sb-runtime specifically, but the architectural object that matters for AGT is the receipt format, not the signer. Three backends map cleanly to the AGT integration model:

- **sb-runtime** is a self-contained Cedar + sandbox + receipts binary. It is the right choice when operators want all three layers delivered as one unit, particularly for constrained deployments (edge, CI, developer workstations) where a Docker/k3s dependency is disproportionate.
- **nono** is the recommended Linux sandbox primitive for operators whose architecture puts the sandbox layer ahead of the receipts layer, or who are already standardizing on it. An sb-runtime deployment can delegate the sandbox layer to nono entirely and keep only Cedar + receipt signing local (see [Composing sb-runtime with nono](#composing-sb-runtime-with-nono) below).
- **OpenShell** remains the coarser-grained container-based alternative for teams already running Docker/k3s infrastructure. Receipt format compatibility is equivalent in principle; a receipt-emitting OpenShell path is not yet upstream.

All three paths emit receipts in the same format and verify with the same tooling. The [AGT Integration Profile](https://github.com/VeritasActa/agt-integration-profile) normatively maps AGT primitives to the receipt format regardless of signer choice.

---

## Why sb-runtime?

sb-runtime and other AGT runtime backends sit at different points on the build-vs-buy spectrum:

| Property | OpenShell | nono | sb-runtime |
|---|:---:|:---:|:---:|
| Container orchestration | ✅ (Docker/k3s) | — | — |
| Kernel sandbox (Landlock / Seatbelt) | — | ✅ library | ✅ built-in |
| Cedar policy evaluation | — | — | ✅ |
| Ed25519 signed decision receipts | — | — | ✅ |
| Veritas Acta conformance | — | — | ✅ |
| Single-binary deployment | — | — | ✅ |
| Multi-OS today | Linux only | Linux + macOS | Linux x86_64 (macOS/Win planned) |
| Library vs drop-in | Infrastructure | Library | Drop-in |

sb-runtime is the right pick when:

- You want Cedar policy + Landlock/seccomp + signed receipts as one artifact, not a stack to assemble.
- Your deployment target is constrained (edge, CI, developer workstation) and a Docker/k3s dependency is disproportionate.
- External auditability of decisions matters: receipts verify against `@veritasacta/verify` without trusting AGT or the operator.
- You need the same binary for both Ring 2 (policy-only) and Ring 3 (policy + sandbox + receipts).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Host process                                                     │
│                                                                   │
│  ┌────────────────────────┐   ┌────────────────────────────────┐ │
│  │  AI Agent (Claude,     │   │  sb-runtime (single binary)    │ │
│  │  Codex, custom, etc)   │   │                                │ │
│  │                        │   │  Cedar evaluator    — policy   │ │
│  │  Tool call ────────────────► Receipt signer      — Ed25519  │ │
│  │             ◄──────────────  Landlock/seccomp    — Ring 3   │ │
│  │  (allow / deny +       │   │  JCS canonicalizer  — RFC 8785 │ │
│  │   signed receipt)      │   │                                │ │
│  └────────────────────────┘   └────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Receipts store (filesystem, S3, Rekor — configurable)        │ │
│  │  Each decision emits a receipt that chains via                │ │
│  │  previousReceiptHash and verifies with @veritasacta/verify.   │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**Request flow:**

1. Agent issues a tool call (e.g., `shell:curl`, `file:write`).
2. **sb-runtime Cedar evaluator** checks policy — Ring 2 decision made here.
3. If Ring 3 is enabled, the action runs inside the Landlock + seccomp sandbox.
4. sb-runtime signs a decision receipt (JCS canonical + Ed25519) and writes it to the configured receipts store.
5. Return value to the agent includes the decision and the receipt ID for later audit.

External auditors verify the receipt with:

```bash
npx @veritasacta/verify <receipt.json> --jwks https://operator.example/jwks
```

No trust in AGT or sb-runtime required. The signature chain is self-describing.

---

## Setup

### Option A: Python provider shim (in-process)

Install the Python wrapper that exposes sb-runtime as an AGT `GovernanceProvider`:

```bash
pip install sb-runtime-agt
```

```python
from agent_runtime import AgentRuntime
from sb_runtime_agt import SbRuntimeProvider

provider = SbRuntimeProvider(
    policy_dir="./policies",
    receipts_dir="./receipts",
    ring=3,  # Ring 2 (policy only) or Ring 3 (policy + sandbox + receipts)
    operator_key="~/.config/sb-runtime/operator.key",
)

runtime = AgentRuntime(provider=provider)
```

The provider is field-compatible with AGT's existing `GovernanceProvider` contract; no changes to agent code are required when swapping between OpenShell and sb-runtime backends.

See the [runnable example](../../examples/sb-runtime-governed/) for a complete demo.

### Option B: Standalone binary (production / edge)

Run sb-runtime as a sidecar or direct binary wrapper:

```bash
# Install (prebuilt binary for Linux x86_64)
curl -fsSL https://github.com/ScopeBlind/sb-runtime/releases/latest/download/sb-runtime-linux-x86_64 \
    -o /usr/local/bin/sb-runtime && chmod +x /usr/local/bin/sb-runtime

# Wrap your agent process
sb-runtime run \
    --policy-dir ./policies \
    --receipts-dir ./receipts \
    --ring 3 \
    --operator-key ~/.config/sb-runtime/operator.key \
    -- claude
```

Agent code is unchanged; sb-runtime intercepts syscalls via Landlock + seccomp and evaluates Cedar policy on each governed action.

### Policy example

```cedar
// policies/http.cedar
permit(
    principal,
    action == Action::"http:POST",
    resource
) when {
    resource.host like "api.github.com" &&
    principal.trust_score >= 0.5
};

forbid(
    principal,
    action == Action::"http:POST",
    resource
) when {
    resource.host == "169.254.169.254"  // Block cloud metadata endpoint
};
```

---

## Ring 2 vs Ring 3

sb-runtime supports both execution rings from the same binary:

**Ring 2 (userspace policy only):**

- Cedar policy evaluation
- Decision receipts signed and emitted
- No kernel-level sandboxing
- Use when the host already provides isolation (containers, VMs)

**Ring 3 (policy + sandbox + receipts):**

- Everything in Ring 2
- Landlock filesystem restrictions (allowed paths only)
- seccomp syscall filtering
- Irreversible privilege drop before tool execution
- Use when sb-runtime is the innermost isolation boundary

Both rings produce receipts in the same Veritas Acta format; the `payload.ring` field distinguishes them. Verifiers can require Ring 3 receipts for high-assurance contexts while accepting Ring 2 for lower-risk operations.

---

## Policy Layering Example

sb-runtime can be deployed alone, or composed with nono (recommended for Linux deployments that want a dedicated sandbox primitive) or OpenShell (for container-based infrastructure) as outer defense-in-depth layers. A single agent action passes through layers:

```
Agent: "I want to POST to https://api.github.com/repos/org/repo/issues"

sb-runtime (Ring 3):
  ✅ Cedar policy allows "http:POST:api.github.com/*"
  ✅ Landlock permits /tmp read, denies ~/.ssh
  ✅ seccomp permits network syscalls
  → ALLOW + signed receipt (SHA-256: 4b3f7c2a...)

Result: Action executes inside sandbox; receipt lands at ./receipts/
```

If policy denies:

```
Agent: "I want to POST to https://169.254.169.254/metadata"

sb-runtime (Ring 3):
  ❌ Cedar forbids "http:POST:169.254.169.254/*"
  → DENY + signed denial receipt (proves the block happened, not just logged)

Result: Action blocked before syscall; receipt emitted to receipts store.
```

The denial receipt is verifiable offline by external auditors — they can confirm the operator's sb-runtime instance enforced the policy without needing access to live logs.

---

## sb-runtime Primitive Mapping to AGT

| AGT primitive | sb-runtime equivalent | Notes |
|---|---|---|
| `GovernanceProvider` contract | `SbRuntimeProvider` (Python shim) or CLI wrapper | Drop-in alternative to OpenShell provider |
| Policy engine | Cedar (AWS) | YAML → Cedar conversion available; OPA/Rego bridge planned |
| Audit log | `receipts/` directory | Each decision is a JCS-canonical, Ed25519-signed JSON file |
| Execution Ring 2 | `--ring 2` flag | Policy evaluation without sandbox |
| Execution Ring 3 | `--ring 3` flag (Linux x86_64 with `linux-sandbox` feature) | Cedar + Landlock + seccomp + receipts |
| Kill switch | SIGTERM to sb-runtime process | Cleanly flushes in-flight receipts before exit |
| Trust score input | Cedar principal attribute `trust_score` | Set per-request by the provider |

---

## Receipt Format

sb-runtime emits receipts in the [Veritas Acta format](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) (IETF I-D), the same format that landed in [Tutorial 33](../tutorials/33-offline-verifiable-receipts.md).

Each receipt contains:

- `kid` — operator signing key identifier (JWK thumbprint)
- `issuer` — operator identity
- `issued_at` — decision timestamp
- `algorithm` — `ed25519`
- `payload.policy_id` — Cedar policy pack identifier
- `payload.policy_hash` — SHA-256 of evaluated policy content
- `payload.decision` — `allow` | `deny` | `require_approval`
- `payload.ring` — `2` or `3`
- `payload.action` — tool call serialization
- `payload.agent_id` — calling agent identity
- `payload.previousReceiptHash` — chain link
- `signature` — Ed25519 signature over JCS-canonicalized envelope

See the [AGT Integration Profile](https://github.com/VeritasActa/agt-integration-profile) for the full field mapping and conformance requirements.

---

## Monitoring

sb-runtime exposes metrics compatible with AGT's existing OpenTelemetry patterns:

- `sb_runtime_decisions_total{result="allow|deny|error"}`
- `sb_runtime_ring{ring="2|3"}`
- `sb_runtime_receipts_emitted_total`
- `sb_runtime_receipt_chain_length{agent_id="..."}`
- `sb_runtime_sandbox_violations_total{syscall="..."}` (Ring 3 only)

Receipts themselves are audit-grade; the metrics are for operational observability.

---

## Composing sb-runtime with nono

For Linux deployments where [nono](https://github.com/always-further/nono) is the preferred sandbox primitive, the two compose naturally. sb-runtime contributes Cedar evaluation + receipt signing; nono contributes the kernel-level sandbox.

```
┌───────────────────────────────────────────────────────────────┐
│  Host                                                          │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  nono (sandbox layer)                                     │ │
│  │    Landlock + Seatbelt capabilities, syscall restrictions │ │
│  │                                                           │ │
│  │   ┌────────────────────────────────────────────────────┐ │ │
│  │   │  sb-runtime (--ring 2, sandbox-external)            │ │ │
│  │   │    Cedar policy evaluation                          │ │ │
│  │   │    Receipt signing (JCS + Ed25519)                  │ │ │
│  │   │    Agent process (Claude, Codex, custom, etc.)      │ │ │
│  │   └────────────────────────────────────────────────────┘ │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

In this composition, sb-runtime runs in `--ring 2` mode (policy + receipts, no internal sandbox) so there is no overlap with nono's kernel sandbox. The receipt produced is byte-identical to a Ring 2 receipt from a standalone sb-runtime deployment; the only difference is that the process lives inside a nono capability set rather than inside sb-runtime's own Landlock + seccomp layer.

Operators adopting this pattern:

1. Install nono and define the sandbox policy (the file/network/syscall capabilities the agent process needs). See [nono documentation](https://nono.sh/) for the capability model.
2. Run sb-runtime with `--ring 2` rather than `--ring 3`. Ring 3 would duplicate sandbox work that nono is already doing.
3. Receipts land in the configured `--receipts-dir`. They verify with `@veritasacta/verify` regardless of which sandbox layer wrapped the process, because the sandbox choice is not part of the receipt's trust boundary: the receipt attests the Cedar decision and the signer identity, not the sandbox configuration.

This composition is the recommended path for operators who already trust nono's sandbox model and want Veritas Acta-conformant decision receipts layered on top. The provider shim (`agent-governance-python/agent-runtime/sb_runtime_agt`, landing in a follow-up PR) exposes this composition as a first-class option alongside the standalone sb-runtime path.

---

## FAQ

**Q: Does sb-runtime replace OpenShell?**
Not necessarily. OpenShell is a container-based runtime; sb-runtime is a single-binary runtime. They solve the same problem at different deployment tiers. A team that already has OpenShell in production can run sb-runtime alongside as a Ring 3 backend for specific high-assurance workflows, or use it standalone for edge / CI / developer environments where container infrastructure is disproportionate.

**Q: What about nono?**
[nono](https://github.com/always-further/nono) is the recommended Linux sandbox primitive for Veritas Acta deployments. Its capability-based model (Landlock on Linux, Seatbelt on macOS) is more mature and more battle-tested than sb-runtime's own built-in sandbox, which is a convenience for single-binary deployments rather than a competing abstraction. For operators whose deployment pattern is "sandbox first, receipts layered on top", running sb-runtime in `--ring 2` mode inside a nono sandbox is the recommended path. The composition is documented in [Composing sb-runtime with nono](#composing-sb-runtime-with-nono) above.

**Q: Does sb-runtime work on macOS / Windows?**
v0.1 ships Cedar policy + signed receipts on all platforms; Landlock-based Ring 3 is Linux x86_64 only. macOS Seatbelt support and Windows AppContainer support are tracked in sb-runtime issues [#3](https://github.com/ScopeBlind/sb-runtime/issues/3) and [#4](https://github.com/ScopeBlind/sb-runtime/issues/4). Linux aarch64 explicitly refuses to run Ring 3 rather than silently weakening the sandbox; tracked in [#1](https://github.com/ScopeBlind/sb-runtime/issues/1).

**Q: Can I verify receipts without installing sb-runtime?**
Yes. Receipts are in the Veritas Acta format and verify with `npx @veritasacta/verify` (Apache-2.0, no AGT or sb-runtime dependencies). An auditor with just the receipt file and the operator's public key can confirm every decision sb-runtime made.

**Q: Is sb-runtime open source?**
Apache-2.0. The GitHub repository is [ScopeBlind/sb-runtime](https://github.com/ScopeBlind/sb-runtime).

**Q: How does sb-runtime handle key rotation?**
The operator signing key is specified at start-time via `--operator-key`. Rotation is handled by restarting sb-runtime with a new key and publishing the updated JWKS to the configured discovery endpoint. Receipt chains span key rotations via `previousReceiptHash` regardless of which key signed each link.

---

## Related

- [sb-runtime on GitHub](https://github.com/ScopeBlind/sb-runtime) — Source, issues, releases
- [Tutorial 33 — Offline-Verifiable Decision Receipts](../tutorials/33-offline-verifiable-receipts.md) — Receipt format, verification, CI integration
- [AGT Integration Profile](https://github.com/VeritasActa/agt-integration-profile) — Normative field mapping for AGT ↔ Veritas Acta conformance
- [`@veritasacta/verify`](https://github.com/VeritasActa/verify) — Reference verifier (Apache-2.0, offline, CLI)
- [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — IETF Internet-Draft
- [examples/sb-runtime-governed/](../../examples/sb-runtime-governed/) — Runnable Ring 2 / Ring 3 demo (coming with PR 3)
- [OpenShell Integration](openshell.md) — Sibling integration guide for container-based deployments
