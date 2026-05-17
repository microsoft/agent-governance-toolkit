<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 22 — Go module (`agentmesh`)

Build governance-aware AI agents in Go. The `agentmesh` module provides
Ed25519 cryptographic identity, trust scoring, declarative policy evaluation,
and hash-chain audit logging — all in a single `go get`.

> **Target runtime:** Go 1.21+
> **Module:** `github.com/microsoft/agent-governance-toolkit/agent-governance-golang`
> **Package:** `agentmesh`

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Evaluate a policy in 5 lines of Go |
| [AgentMeshClient](#agentmeshclient) | Unified governance pipeline — identity + trust + policy + audit |
| [PolicyEngine](#policyengine) | Declarative rules, YAML policies, rate limiting, approval |
| [TrustManager](#trustmanager) | Trust scoring with decay, tiers, and file persistence |
| [AuditLogger](#auditlogger) | Hash-chain audit logging and verification |
| [AgentIdentity](#agentidentity) | Ed25519 key pairs, DIDs, signing, JSON serialisation |
| [Loading Policies from YAML](#loading-policies-from-yaml) | File-based policy configuration |
| [Full Governance Pipeline](#full-governance-pipeline) | End-to-end example |
| [Cross-Reference](#cross-reference) | Equivalent Python and TypeScript tutorials |
| [Next Steps](#next-steps) | Where to go from here |

---

## Prerequisites

- **Go 1.21+**
- Familiarity with Go modules (`go.mod`)
- Recommended: read [Tutorial 01 — Policy Engine](01-policy-engine.md) for
  governance concepts

---

## Installation

```bash
go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang
```

The module has a single external dependency — `gopkg.in/yaml.v3` for YAML
policy parsing.

```bash
# Verify the install
go list -m github.com/microsoft/agent-governance-toolkit/agent-governance-golang
```

---

## Quick Start

Five lines to create a governed agent:

```go
package main

import (
    "fmt"
    agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"
)

func main() {
    client, err := agentmesh.NewClient("my-agent")
    if err != nil {
        panic(err)
    }

    result, _ := client.ExecuteWithGovernance("data.read", nil)
    fmt.Println("Allowed:", result.Allowed)     // true
    fmt.Println("Decision:", result.Decision)    // allow
}
```

When no policy rules are provided, the default decision is **deny** — secure by
default.

Or configure at creation with functional options:

```go
client, err := agentmesh.NewClient("my-agent",
    agentmesh.WithCapabilities([]string{"data.read", "data.write"}),
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read",  Effect: agentmesh.Allow},
        {Action: "data.write", Effect: agentmesh.Allow},
        {Action: "*",          Effect: agentmesh.Deny},
    }),
)
```

---

## AgentMeshClient

`AgentMeshClient` is the recommended entry point. It wires together identity,
trust, policy, and audit into a single governance-aware pipeline.

### Creating a Client

```go
// Default client — generates identity, no policy rules (deny-all)
client, err := agentmesh.NewClient("analyst-001")

// Client with functional options
client, err := agentmesh.NewClient("analyst-001",
    agentmesh.WithCapabilities([]string{"data.read", "search"}),
    agentmesh.WithTrustConfig(agentmesh.TrustConfig{
        InitialScore:  0.8,
        DecayRate:     0.01,
        RewardFactor:  1.0,
        PenaltyFactor: 1.5,
        TierThresholds: agentmesh.TierThresholds{High: 0.8, Medium: 0.5},
    }),
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read", Effect: agentmesh.Allow},
        {Action: "*",         Effect: agentmesh.Deny},
    }),
)
```

### Functional Options

| Option | Description |
|--------|-------------|
| `WithCapabilities([]string)` | Set capabilities on the generated identity |
| `WithTrustConfig(TrustConfig)` | Override default trust configuration |
| `WithPolicyRules([]PolicyRule)` | Set initial policy rules |

### Accessing Components

```go
// Identity
fmt.Println("DID:", client.Identity.DID)
fmt.Println("Capabilities:", client.Identity.Capabilities)

// Trust
score := client.Trust.GetTrustScore(client.Identity.DID)
fmt.Println("Trust:", score.Overall, "Tier:", score.Tier)

// Audit
fmt.Println("Chain valid:", client.Audit.Verify())
```

### The Governance Pipeline

`ExecuteWithGovernance` runs the full pipeline: evaluate → log → trust update.

```go
result, err := client.ExecuteWithGovernance("data.read", nil)

fmt.Println("Allowed:", result.Allowed)
fmt.Println("Decision:", result.Decision)
fmt.Println("Trust:", result.TrustScore.Overall)
fmt.Println("Audit hash:", result.AuditEntry.Hash)
```

When the decision is `Allow`, trust increases. When it's `Deny`, trust
decreases. The audit entry is always appended to the chain.

---

## PolicyEngine

The `PolicyEngine` evaluates actions against a set of rules. Rules are evaluated
in order; **first match wins**. The default decision when no rule matches is
**Deny**.

### §3.1 Policy Rules

```go
rules := []agentmesh.PolicyRule{
    {Action: "data.read",   Effect: agentmesh.Allow},
    {Action: "data.write",  Effect: agentmesh.Allow},
    {Action: "deploy.*",    Effect: agentmesh.Review},
    {Action: "shell.*",     Effect: agentmesh.Deny},
    {Action: "*",           Effect: agentmesh.Deny},  // catch-all
}

engine := agentmesh.NewPolicyEngine(rules)

fmt.Println(engine.Evaluate("data.read", nil))   // allow
fmt.Println(engine.Evaluate("shell.exec", nil))   // deny
fmt.Println(engine.Evaluate("deploy.prod", nil))  // review
fmt.Println(engine.Evaluate("unknown", nil))       // deny (catch-all)
```

### §3.2 Decision Types

| Decision | Constant | Description |
|----------|----------|-------------|
| Allow | `agentmesh.Allow` | Action is permitted |
| Deny | `agentmesh.Deny` | Action is blocked |
| Review | `agentmesh.Review` | Action requires human review |
| Rate Limit | `agentmesh.RateLimit` | Action is rate-limited |
| Requires Approval | `agentmesh.RequiresApproval` | Action needs explicit approval |

### §3.3 Wildcard Patterns

The engine supports glob-style action matching:

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `*` | Everything | — |
| `data.*` | `data.read`, `data.write` | `shell.exec` |
| `shell.*` | `shell.exec`, `shell.ls` | `data.read` |
| `data.read` | `data.read` (exact) | `data.write` |

### §3.4 Conditional Rules

Rules can include conditions matched against a context map:

```go
rules := []agentmesh.PolicyRule{
    {
        Action:     "deploy.*",
        Effect:     agentmesh.Deny,
        Conditions: map[string]interface{}{"environment": "production"},
    },
    {
        Action: "deploy.*",
        Effect: agentmesh.Allow,
    },
}

engine := agentmesh.NewPolicyEngine(rules)

// Production deploys are denied
prodCtx := map[string]interface{}{"environment": "production"}
fmt.Println(engine.Evaluate("deploy.app", prodCtx))  // deny

// Staging deploys are allowed (conditions don't match first rule)
stagingCtx := map[string]interface{}{"environment": "staging"}
fmt.Println(engine.Evaluate("deploy.app", stagingCtx))  // allow
```

The engine supports `$and`, `$or`, `$not`, and comparison operators (`$gt`,
`$gte`, `$lt`, `$lte`, `$ne`, `$in`) in conditions.

### §3.5 Rate Limiting

Rules with `MaxCalls` and `Window` enable per-action rate limiting:

```go
rules := []agentmesh.PolicyRule{
    {
        Action:   "api.call",
        Effect:   agentmesh.Allow,
        MaxCalls: 5,
        Window:   "1m",  // 5 calls per minute
    },
}

engine := agentmesh.NewPolicyEngine(rules)

for i := 0; i < 5; i++ {
    fmt.Println(engine.Evaluate("api.call", nil))  // allow
}
fmt.Println(engine.Evaluate("api.call", nil))  // rate_limit
```

### §3.6 Approval Requirements

```go
rules := []agentmesh.PolicyRule{
    {
        Action:       "deploy.production",
        Effect:       agentmesh.Allow,
        MinApprovals: 2,
        Approvers:    []string{"lead", "sre"},
    },
}

engine := agentmesh.NewPolicyEngine(rules)
fmt.Println(engine.Evaluate("deploy.production", nil))  // requires_approval
```

---

## Loading Policies from YAML

Store policies in version-controlled YAML files:

```yaml
# policies/governance.yaml
rules:
  - action: "data.read"
    effect: allow
  - action: "data.write"
    effect: allow
    conditions:
      role: admin
  - action: "shell.*"
    effect: deny
  - action: "deploy.*"
    effect: review
  - action: "*"
    effect: deny
```

```go
engine := agentmesh.NewPolicyEngine(nil)
err := engine.LoadFromYAML("policies/governance.yaml")
if err != nil {
    log.Fatalf("failed to load policy: %v", err)
}

fmt.Println(engine.Evaluate("data.read", nil))  // allow
```

`LoadFromYAML` replaces the engine's existing rule set; calling it again on a
config reload won't double the rules. Use `MergeFromYAML` when composing rules
from multiple files.

---

## TrustManager

The `TrustManager` tracks per-agent trust scores on a **0.0–1.0** scale with
configurable tiers, decay, and file persistence.

### §5.1 Trust Tiers

| Tier | Score Range | Description |
|------|-------------|-------------|
| `low` | 0.0–0.49 | Untrusted or new agent |
| `medium` | 0.5–0.79 | Provisional trust |
| `high` | 0.8–1.0 | Fully trusted |

### §5.2 Basic Usage

```go
tm := agentmesh.NewTrustManager(agentmesh.DefaultTrustConfig())

// New agent starts at 0.5 (medium tier)
score := tm.GetTrustScore("agent-x")
fmt.Println(score.Overall)  // 0.5
fmt.Println(score.Tier)     // medium

// Record successes — trust increases
tm.RecordSuccess("agent-x", 0.05)
tm.RecordSuccess("agent-x", 0.05)
score = tm.GetTrustScore("agent-x")
fmt.Println(score.Overall)  // ~0.59

// Record failure — trust decreases (asymmetric: penalty factor = 1.5×)
tm.RecordFailure("agent-x", 0.1)
score = tm.GetTrustScore("agent-x")
fmt.Println(score.Overall, score.Tier)
```

### §5.3 Custom Configuration

```go
cfg := agentmesh.TrustConfig{
    InitialScore:  0.8,
    DecayRate:     0.02,
    RewardFactor:  1.0,
    PenaltyFactor: 2.0,
    TierThresholds: agentmesh.TierThresholds{
        High:   0.8,
        Medium: 0.5,
    },
    MinInteractions: 5,
}

tm := agentmesh.NewTrustManager(cfg)
score := tm.GetTrustScore("high-trust-agent")
fmt.Println(score.Overall)  // 0.8
fmt.Println(score.Tier)     // high
```

### §5.4 Peer Verification

Verify a peer agent's identity and trust score in one call:

```go
peer, _ := agentmesh.GenerateIdentity("peer-agent", nil)

result, err := tm.VerifyPeer("peer-agent", peer)
fmt.Println("Verified:", result.Verified)
fmt.Println("Score:", result.Score.Overall)
```

### §5.5 File Persistence

Enable persistence to survive process restarts:

```go
cfg := agentmesh.TrustConfig{
    PersistPath: "trust-state.json",
    // ... other config ...
}
tm := agentmesh.NewTrustManager(cfg)

// Scores are automatically saved after each update
tm.RecordSuccess("agent-x", 0.05)
// trust-state.json now contains the serialised score state

// On next startup, scores are loaded from disk automatically
tm2 := agentmesh.NewTrustManager(cfg)
score := tm2.GetTrustScore("agent-x")
fmt.Println(score.Overall)  // restored score
```

---

## AuditLogger

The `AuditLogger` provides an append-only, hash-chain-linked audit trail. Each
entry's SHA-256 hash incorporates the previous entry's hash, creating a
tamper-evident chain.

### §6.1 Logging Events

```go
logger := agentmesh.NewAuditLogger()

entry := logger.Log("agent-001", "data.read", agentmesh.Allow)
fmt.Println("Hash:", entry.Hash)
fmt.Println("Prev:", entry.PreviousHash)  // empty for genesis entry
```

### §6.2 Hash-Chain Integrity

```go
logger := agentmesh.NewAuditLogger()

logger.Log("agent-1", "data.read",   agentmesh.Allow)
logger.Log("agent-1", "data.write",  agentmesh.Deny)
logger.Log("agent-2", "report.send", agentmesh.Allow)

// Verify the entire chain
fmt.Println(logger.Verify())  // true
```

**How the chain works:**

```
  Entry 0            Entry 1            Entry 2
  ┌──────────┐       ┌──────────┐       ┌──────────┐
  │ hash: A  │──────▶│ prev: A  │──────▶│ prev: B  │
  │ prev: "" │       │ hash: B  │       │ hash: C  │
  └──────────┘       └──────────┘       └──────────┘

  hash = SHA-256(timestamp | agentID | action | decision | previousHash)
```

### §6.3 Retention Limits

Set `MaxEntries` to limit memory usage in long-running services:

```go
logger := agentmesh.NewAuditLogger()
logger.MaxEntries = 1000  // keep last 1000 entries

// Old entries are evicted when the limit is exceeded
for i := 0; i < 1500; i++ {
    logger.Log("agent", fmt.Sprintf("action-%d", i), agentmesh.Allow)
}
// Chain still verifies (eviction is chain-aware)
fmt.Println(logger.Verify())  // true
```

### §6.4 Filtering and Querying

```go
filter := agentmesh.AuditFilter{
    AgentID: "agent-1",
}
entries := logger.GetEntries(filter)
fmt.Println("Agent-1 entries:", len(entries))

// Filter by decision
deny := agentmesh.Deny
filter = agentmesh.AuditFilter{
    Decision: &deny,
}
denied := logger.GetEntries(filter)
fmt.Println("Denied entries:", len(denied))
```

### §6.5 Exporting the Audit Trail

```go
jsonStr, err := logger.ExportJSON()
if err != nil {
    log.Fatal(err)
}
fmt.Println(jsonStr)
```

---

## AgentIdentity

The `AgentIdentity` provides Ed25519-based cryptographic identity with DID
identifiers and data signing.

### §7.1 Generating an Identity

```go
identity, err := agentmesh.GenerateIdentity(
    "researcher-agent",
    []string{"data.read", "search"},
)
if err != nil {
    log.Fatal(err)
}

fmt.Println("DID:", identity.DID)                // did:agentmesh:researcher-agent
fmt.Println("Capabilities:", identity.Capabilities)
fmt.Println("Public key:", len(identity.PublicKey), "bytes")  // 32 bytes
```

### §7.2 Signing and Verifying

```go
data := []byte("important message")

// Sign
signature, err := identity.Sign(data)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Signature:", len(signature), "bytes")  // 64 bytes

// Verify
fmt.Println("Valid:", identity.Verify(data, signature))  // true

// Tampered data fails
fmt.Println("Tampered:", identity.Verify([]byte("wrong"), signature))  // false
```

### §7.3 JSON Serialisation

Export the public portion of an identity for sharing:

```go
jsonBytes, err := identity.ToJSON()
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonBytes))
// {"did":"did:agentmesh:researcher-agent","public_key":"...","capabilities":["data.read","search"]}

// Reconstruct from JSON (public key only)
imported, err := agentmesh.FromJSON(jsonBytes)
fmt.Println("Imported DID:", imported.DID)
fmt.Println("Can verify:", imported.Verify(data, signature))  // true
```

---

## Full Governance Pipeline

End-to-end example combining all subsystems:

```go
package main

import (
    "fmt"
    "log"

    agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"
)

func main() {
    // 1. Create a governed client
    client, err := agentmesh.NewClient("research-agent",
        agentmesh.WithCapabilities([]string{"data.read", "search.web"}),
        agentmesh.WithTrustConfig(agentmesh.TrustConfig{
            InitialScore:  0.5,
            DecayRate:     0.01,
            RewardFactor:  1.0,
            PenaltyFactor: 1.5,
            TierThresholds: agentmesh.TierThresholds{High: 0.8, Medium: 0.5},
        }),
        agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
            {Action: "data.read",  Effect: agentmesh.Allow},
            {Action: "search.*",   Effect: agentmesh.Allow},
            {Action: "data.write", Effect: agentmesh.Review},
            {Action: "*",          Effect: agentmesh.Deny},
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Agent DID:", client.Identity.DID)

    // 2. Execute governed actions
    actions := []string{"data.read", "search.web", "data.write", "shell.exec"}
    for _, action := range actions {
        result, _ := client.ExecuteWithGovernance(action, nil)
        status := "✅ allowed"
        if !result.Allowed {
            status = "❌ denied"
        }
        fmt.Printf("  %s → %s (trust: %.2f, tier: %s)\n",
            action, status, result.TrustScore.Overall, result.TrustScore.Tier)
    }

    // 3. Verify audit chain
    fmt.Println("\nAudit chain valid:", client.Audit.Verify())

    // 4. Export audit trail
    jsonStr, _ := client.Audit.ExportJSON()
    fmt.Println("Audit JSON:", jsonStr[:80], "...")
}
```

**Expected output:**

```
Agent DID: did:agentmesh:research-agent
  data.read  → ✅ allowed (trust: 0.54, tier: medium)
  search.web → ✅ allowed (trust: 0.59, tier: medium)
  data.write → ❌ denied  (trust: 0.44, tier: low)
  shell.exec → ❌ denied  (trust: 0.28, tier: low)

Audit chain valid: true
Audit JSON: [{"timestamp":"2025-07-15T10:30:00Z","agent_id":"did:agentmesh:resear ...
```

---

## Cross-Reference

| Go module feature | Python Equivalent | Tutorial |
|----------------|-------------------|----------|
| `PolicyEngine` | `agent_os.policy` | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |
| `TrustManager` | `agent_os.trust` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| `AuditLogger` | `agent_os.audit` | [Tutorial 04 — Audit & Compliance](./04-audit-and-compliance.md) |
| `AgentIdentity` | `agent_os.identity` | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| `AgentMeshClient` | `AgentMeshClient` | [Tutorial 20 — TypeScript package](./20-typescript-sdk.md) |

> **Note:** The Go module uses a 0.0–1.0 trust scale with three tiers, while the
> Rust crate uses 0–1000 with five tiers. Both use the same governance concepts
> and YAML policy format.

---

## Source Files

| Component | Location |
|-----------|----------|
| Client + options | `agent-governance-golang/client.go` |
| Type definitions | `agent-governance-golang/types.go` |
| `PolicyEngine` | `agent-governance-golang/policy.go` |
| `TrustManager` | `agent-governance-golang/trust.go` |
| `AuditLogger` | `agent-governance-golang/audit.go` |
| `AgentIdentity` | `agent-governance-golang/identity.go` |
| Conflict resolution | `agent-governance-golang/conflict.go` |
| Metrics | `agent-governance-golang/metrics.go` |
| Tests | `agent-governance-golang/*_test.go` |

---

## Next Steps

- **Run the tests** to see the module in action:
  ```bash
  cd agent-governance-golang
  go test ./...
  ```
- **Load YAML policies** from the repository's `policies/` directory
- **Enable trust persistence** with `PersistPath` to retain scores across
  restarts
- **Verify audit chains** in your CI/CD pipeline — call `Verify()` as a
  post-deployment check
- **Explore the Rust crate** tutorial ([Tutorial 21](./21-rust-sdk.md)) for the
  Rust equivalent
- **Read the Python tutorials** (01–04) for detailed governance concepts
