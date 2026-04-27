# AgentMesh Go module

Go module for the AgentMesh governance framework — identity, trust scoring, policy evaluation, tamper-evident audit logging, MCP security scanning, execution privilege rings, agent lifecycle management, SLO tracking, shadow discovery, prompt defense, and native Go integrations.

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
| `(*PolicyEngine).AddBackend(backend)` | Register an external policy backend |
| `(*PolicyEngine).LoadRego(options)` | Register an OPA/Rego backend |
| `(*PolicyEngine).LoadCedar(options)` | Register a Cedar backend |

### External Policy Backends (`policy_backends.go`)

OPA/Rego and Cedar support with fail-closed evaluation paths.

| Type / Function | Description |
|---|---|
| `NewOPABackend(options)` | Create an OPA backend with remote, CLI, or built-in modes |
| `NewCedarBackend(options)` | Create a Cedar backend with CLI or built-in modes |
| `OPAOptions` | Configure OPA URL, package/query, timeout, and Rego content |
| `CedarOptions` | Configure Cedar policy content, entities, schema, and timeout |

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

### SRE / SLOs (`slo.go`)

Minimal service-level objective tracking for Go applications.

| Type / Function | Description |
|---|---|
| `NewSLOEngine(objectives)` | Create an engine with named objectives |
| `(*SLOEngine).AddObjective(objective)` | Register a new SLO |
| `(*SLOEngine).RecordEvent(name, success, latency)` | Record a request or operation outcome |
| `(*SLOEngine).Evaluate(name)` | Compute current attainment and error budget |

### Framework Integrations (`middleware.go`)

Go-native integration helpers built around a composable governance middleware stack.

| Type / Function | Description |
|---|---|
| `GovernedOperation` | Common operation envelope for tool calls, prompts, and request flows |
| `CreateGovernanceMiddlewareStack(config)` | Compose policy, capability guard, prompt defense, audit, and SLO middleware |
| `NewHTTPGovernanceMiddleware(config)` | Create `net/http` middleware backed by the governance stack |
| `GovernOperation(...)` | Wrap a generic operation with the standard governance stack |

`NewHTTPGovernanceMiddleware` now fails closed unless `HTTPMiddlewareConfig.AgentIDResolver`
returns a verified identity. Caller-asserted `X-Agent-ID` values are exposed to policy as
`caller_asserted_agent_id`, but they are no longer treated as trusted `agent_id` values by
default.

For short-lived migrations behind a trusted front door, opt in explicitly:

```go
middleware, err := agentmesh.NewHTTPGovernanceMiddleware(agentmesh.HTTPMiddlewareConfig{
    Policy:                    policy,
    AgentIDResolver:           agentmesh.LegacyTrustedHeaderAgentIDResolver("X-Agent-ID"),
    PromptDefense:             agentmesh.NewPromptDefenseEvaluator(),
    PromptDefenseMaxRiskScore: 24,
})
```

Recommended migration path: wire `AgentIDResolver` to your authenticated reverse proxy,
service mesh, or workload identity layer so it returns a verified agent identity. Use
`LegacyTrustedHeaderAgentIDResolver` only as an explicit compatibility bridge while you move
away from caller-asserted headers.

### Shadow Discovery (`discovery.go`)

Structured SDK discovery for likely unregistered agent tooling across text, processes, config paths, and GitHub repositories.

| Type / Function | Description |
|---|---|
| `DiscoveredAgent` / `DiscoveryEvidence` / `DiscoveryScanResult` | Structured discovery models for evidence-driven results |
| `NewShadowDiscoveryScanner()` | Create a scanner with built-in discovery rules |
| `(*ShadowDiscoveryScanner).ScanText(source, content)` | Scan config or source text for findings |
| `(*ShadowDiscoveryScanner).ScanProcessCommands(commands)` | Scan raw command lines supplied by the caller |
| `(*ShadowDiscoveryScanner).ScanProcesses(processes)` | Produce structured discovery results from process metadata |
| `(*ShadowDiscoveryScanner).ScanCurrentHostProcessList()` | Enumerate and scan the local process list |
| `(*ShadowDiscoveryScanner).ScanConfigPaths(paths, maxDepth)` | Scan config and dependency files across filesystem paths |
| `(*ShadowDiscoveryScanner).ScanGitHubRepositories(client, repos)` | Scan repository contents through the GitHub contents API |
| `NewGitHubDiscoveryClient(token)` | Create a GitHub API client for repository discovery scans |

### Prompt Defense (`promptdefense.go`)

Structured prompt risk evaluation for injection and exfiltration patterns.

| Type / Function | Description |
|---|---|
| `NewPromptDefenseEvaluator()` | Create a prompt defense evaluator |
| `(*PromptDefenseEvaluator).Evaluate(prompt)` | Score a prompt and return structured findings |

## License

See repository root [LICENSE](../LICENSE).
