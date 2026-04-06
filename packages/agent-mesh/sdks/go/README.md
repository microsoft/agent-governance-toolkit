# AgentMesh Go SDK

Go SDK for the AgentMesh governance framework — identity, trust scoring, policy evaluation, tamper-evident audit logging, and MCP security enforcement primitives.

## Install

```bash
go get github.com/microsoft/agent-governance-toolkit/sdks/go
```

For MCP-only integrations, you can use the standalone wrapper module:

```bash
go get github.com/microsoft/agent-governance-toolkit/packages/mcp-governance-go
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

## MCP Security Quick Start

```go
package main

import (
	"log"
	"time"

	agentmesh "github.com/microsoft/agent-governance-toolkit/sdks/go"
)

func main() {
	authenticator, err := agentmesh.NewMcpSessionAuthenticator(agentmesh.McpSessionAuthenticatorConfig{
		SessionTTL:            15 * time.Minute,
		MaxConcurrentSessions: 4,
	})
	if err != nil {
		log.Fatal(err)
	}

	session, err := authenticator.CreateSession("agent-007")
	if err != nil {
		log.Fatal(err)
	}

	gateway, err := agentmesh.NewMcpGateway(agentmesh.McpGatewayConfig{
		Authenticator: authenticator,
		Policy:        agentmesh.DefaultMcpPolicy(),
	})
	if err != nil {
		log.Fatal(err)
	}

	decision, err := gateway.InterceptToolCall(agentmesh.McpToolCallRequest{
		SessionToken:    session.Token,
		ToolName:        "search.docs",
		ToolDescription: "Search product documentation",
		ToolSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
		},
		Payload: map[string]any{"query": "OWASP MCP"},
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("allowed=%v decision=%s threats=%d", decision.Allowed, decision.Decision, len(decision.Threats))
}
```

## MCP Documentation

- [MCP HTTP Server Example](./examples/mcp-http-server/README.md)

## API Overview

### Identity (`identity.go`)

Ed25519-based agent identities with DID support.

| Function / Method | Description |
|---|---|
| `GenerateIdentity(agentID, capabilities)` | Create a new agent identity |
| `(*AgentIdentity).Sign(data)` | Sign data with private key |
| `(*AgentIdentity).Verify(data, sig)` | Verify a signature |
| `(*AgentIdentity).ToJSON()` | Serialize public identity |
| `FromJSON(data)` | Deserialize an identity |

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

### MCP Security (`mcp_*.go`, `credential_redactor.go`)

OWASP-aligned MCP defenses for authentication, replay protection, rate limiting, tool scanning, credential redaction, response scanning, and centralized gateway enforcement.

| Function / Method | Description |
|---|---|
| `NewMcpMessageSigner(config)` | Create an HMAC-SHA256 signer with nonce replay protection |
| `(*McpMessageSigner).Sign(envelope)` | Attach timestamp, nonce, and signature |
| `(*McpMessageSigner).Verify(envelope)` | Verify signature, timestamp skew, and nonce freshness |
| `NewMcpSessionAuthenticator(config)` | Create a session authenticator with TTL and concurrency limits |
| `(*McpSessionAuthenticator).CreateSession(agentID)` | Create a cryptographically random session token |
| `(*McpSessionAuthenticator).ValidateSession(token)` | Validate an active, non-expired session |
| `(*McpSessionAuthenticator).RevokeSession(token)` | Revoke a session token |
| `NewMcpSlidingRateLimiter(config)` | Create a per-agent sliding-window rate limiter |
| `(*McpSlidingRateLimiter).Allow(agentID)` | Evaluate and record an MCP request |
| `NewMcpSecurityScanner(config)` | Create a tool-definition scanner with fingerprint registry |
| `(*McpSecurityScanner).ScanTool(name, description, schema)` | Detect hidden instructions, injection, schema abuse, and rug-pulls |
| `NewCredentialRedactor(config)` | Create a secret redactor for logs and payloads |
| `(*CredentialRedactor).Redact(input)` | Redact PEM blocks, API keys, bearer tokens, and connection strings |
| `NewMcpResponseScanner(config)` | Create a response scanner backed by the credential redactor |
| `(*McpResponseScanner).ScanResponse(response)` | Sanitize nested tool responses and return findings |
| `NewMcpGateway(config)` | Create a unified MCP enforcement gateway |
| `(*McpGateway).InterceptToolCall(request)` | Run auth -> rate-limit -> scan -> sign -> audit with fail-closed behavior |
| `DefaultMcpPolicy()` | Return the default allow policy that blocks critical findings |

## License

See repository root [LICENSE](../../LICENSE).
