# Integrating with sb-runtime

Deploy [sb-runtime](https://github.com/ScopeBlind/sb-runtime) as a Ring 2/3 governance backend inside the Agent Governance Toolkit: a single Rust binary that combines Cedar policy evaluation, Landlock + seccomp sandboxing, and Ed25519-signed decision receipts.

> **TL;DR** — sb-runtime is a Veritas Acta-conformant runtime backend. It evaluates Cedar policies for each governed action (Ring 2), optionally sandboxes the action with Landlock + seccomp (Ring 3), and emits a signed decision receipt external auditors can verify without trusting the operator or the backend. Drop-in alternative to OpenShell for teams that want "Cedar + kernel sandbox + receipts" as one unit rather than assembling them separately.

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

sb-runtime can be deployed alone or composed with nono / OpenShell for defense-in-depth. A single agent action passes through layers:

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

## FAQ

**Q: Does sb-runtime replace OpenShell?**
Not necessarily. OpenShell is a container-based runtime; sb-runtime is a single-binary runtime. They solve the same problem at different deployment tiers. A team that already has OpenShell in production can run sb-runtime alongside as a Ring 3 backend for specific high-assurance workflows, or use it standalone for edge / CI / developer environments where container infrastructure is disproportionate.

**Q: What about nono?**
[nono](https://github.com/always-further/nono) is a capability-based sandboxing library (kernel-native primitives: Landlock, Seatbelt). sb-runtime uses similar primitives internally but exposes them as a single binary wrapped with Cedar + receipts. nono is the right choice when a team is building their own sandbox orchestration; sb-runtime is the right choice when a team wants Cedar + Landlock + receipts delivered as one unit.

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
