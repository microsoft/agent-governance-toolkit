# AgentMesh Go SDK

Go SDK for the AgentMesh governance framework — identity, trust scoring, policy evaluation, and tamper-evident audit logging.

## Install

```bash
go get github.com/microsoft/agent-governance-toolkit/sdks/go
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/sdks/go"
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

## License

See repository root [LICENSE](../../LICENSE).
