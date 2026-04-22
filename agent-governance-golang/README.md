# AgentMesh Go module

Go module for the AgentMesh governance framework — identity, trust scoring, policy evaluation, tamper-evident audit logging, MCP security scanning, execution privilege rings, and agent lifecycle management.

## Install

```bash
go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"
)

func main() {
	client, err := agentmesh.NewClient("my-agent",
		agentmesh.WithCapabilities([]string{"data.read", "data.write"}),
		agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
			{Action: "data.read", Effect: agentmesh.Allow},
			{Action: "data.write", Effect: agentmesh.Review},
			{Action: "*", Effect: agentmesh.Deny},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.ExecuteWithGovernance("data.read", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decision: %s, Allowed: %v\n", result.Decision, result.Allowed)
}
```

## API Overview

### Identity (`identity.go`)

Ed25519-based agent identities with DID support.

| Function / Method | Description |
|---|---|
| `GenerateIdentity(agentID, capabilities)` | Create a new agent identity |
| `(*AgentIdentity).Sign(data)` | Sign data with private key |
| `(*AgentIdentity).Verify(data, sig)` | Verify a signature |
| `(*AgentIdentity).ToJSON()` | Serialise public identity |
| `FromJSON(data)` | Deserialise an identity |

### Trust (`trust.go`)

Decay-based trust scoring with asymmetric reward/penalty.

| Function / Method | Description |
|---|---|
| `NewTrustManager(config)` | Create a trust manager |
| `(*TrustManager).VerifyPeer(id, identity)` | Verify a peer |
| `(*TrustManager).GetTrustScore(agentID)` | Get current trust score |
| `(*TrustManager).RecordSuccess(agentID, reward)` | Record a successful interaction |
| `(*TrustManager).RecordFailure(agentID, penalty)` | Record a failed interaction |

### Policy (`policy.go`)

Rule-based policy engine with wildcard and condition matching.

| Function / Method | Description |
|---|---|
| `NewPolicyEngine(rules)` | Create a policy engine |
| `(*PolicyEngine).Evaluate(action, context)` | Evaluate an action |
| `(*PolicyEngine).LoadFromYAML(path)` | Load rules from YAML file |

### Audit (`audit.go`)

SHA-256 hash-chained audit log for tamper detection.

| Function / Method | Description |
|---|---|
| `NewAuditLogger()` | Create an audit logger |
| `(*AuditLogger).Log(agentID, action, decision)` | Append an audit entry |
| `(*AuditLogger).Verify()` | Verify chain integrity |
| `(*AuditLogger).GetEntries(filter)` | Query entries by filter |

### Client (`client.go`)

Unified governance client combining all modules.

| Function / Method | Description |
|---|---|
| `NewClient(agentID, ...Option)` | Create a full client |
| `(*AgentMeshClient).ExecuteWithGovernance(action, params)` | Run action through governance pipeline |

### MCP Security (`mcp.go`)

Detects tool poisoning, typosquatting, hidden instructions, and rug-pull patterns in MCP tool definitions.

| Function / Method | Description |
|---|---|
| `NewMcpSecurityScanner()` | Create a new MCP security scanner |
| `(*McpSecurityScanner).Scan(tool)` | Scan a single tool definition |
| `(*McpSecurityScanner).ScanAll(tools)` | Scan multiple tool definitions |

```go
scanner := agentmesh.NewMcpSecurityScanner()
result := scanner.Scan(agentmesh.McpToolDefinition{
    Name:        "search",
    Description: "Search the web.",
})
fmt.Printf("Safe: %v, Risk: %d\n", result.Safe, result.RiskScore)
```

### Execution Rings (`rings.go`)

Privilege ring model for agent access control (Ring 0 = Admin … Ring 3 = Sandboxed).

| Function / Method | Description |
|---|---|
| `NewRingEnforcer()` | Create a ring enforcer |
| `(*RingEnforcer).Assign(agentID, ring)` | Place an agent in a ring |
| `(*RingEnforcer).GetRing(agentID)` | Get an agent's ring |
| `(*RingEnforcer).CheckAccess(agentID, action)` | Check if action is allowed |
| `(*RingEnforcer).SetRingPermissions(ring, actions)` | Configure ring permissions |

```go
enforcer := agentmesh.NewRingEnforcer()
enforcer.SetRingPermissions(agentmesh.RingStandard, []string{"data.read", "data.write"})
enforcer.Assign("agent-1", agentmesh.RingStandard)
fmt.Println(enforcer.CheckAccess("agent-1", "data.read")) // true
```

### Lifecycle (`lifecycle.go`)

Eight-state lifecycle model with validated transitions.

States: `provisioning` → `active` → `suspended` / `rotating` / `degraded` / `quarantined` → `decommissioning` → `decommissioned`

| Function / Method | Description |
|---|---|
| `NewLifecycleManager(agentID)` | Create a lifecycle manager (starts provisioning) |
| `(*LifecycleManager).State()` | Get current state |
| `(*LifecycleManager).Events()` | Get transition history |
| `(*LifecycleManager).Transition(to, reason, by)` | Perform a validated transition |
| `(*LifecycleManager).CanTransition(to)` | Check if transition is valid |
| `(*LifecycleManager).Activate(reason)` | Convenience: move to active |
| `(*LifecycleManager).Suspend(reason)` | Convenience: move to suspended |
| `(*LifecycleManager).Quarantine(reason)` | Convenience: move to quarantined |
| `(*LifecycleManager).Decommission(reason)` | Convenience: start decommissioning |

```go
lm := agentmesh.NewLifecycleManager("agent-1")
lm.Activate("provisioned")
lm.Suspend("maintenance window")
lm.Activate("maintenance complete")
fmt.Println(lm.State()) // active
```

## License

See repository root [LICENSE](../../LICENSE).
