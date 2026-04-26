# Tutorial 16 — Protocol Bridges (A2A, MCP, IATP)

> **Package:** `agentmesh-platform` · **Time:** 30 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- A2A task envelopes and trust-gated communication
- MCP proxy with policy enforcement and trust thresholds
- IATP attestation and cross-protocol message translation
- Trust-gated communication between heterogeneous agents

---

## Connecting Agents Across Protocols with Trust-Gated Communication

**Prerequisites:** `pip install agentmesh-platform a2a-agentmesh mcp-trust-proxy`
**Modules:** `agentmesh.trust`, `agentmesh.identity`, `a2a_agentmesh`, `mcp_trust_proxy`, `agent_os.integrations.a2a_adapter`

---

## 1. Introduction — Why Protocol Bridges Matter

AI agents speak different protocols. An MCP coding assistant, an A2A task
agent, and an IATP governance node may need to collaborate — but share no
wire format, trust model, or discovery mechanism. Protocol bridges solve
this by translating messages, gating communication on trust, and preserving
audit trails.

The Agent Governance Toolkit ships three bridge components:

| Protocol | Purpose | Key Packages |
|----------|---------|-------------|
| **MCP** (Model Context Protocol) | Trust-gated tool exposure for AI agents | `agentmesh.cli.proxy`, `mcp_trust_proxy` |
| **A2A** (Agent-to-Agent) | Task delegation and agent discovery | `a2a_agentmesh`, `agent_os.integrations.a2a_adapter` |
| **IATP** (Inter-Agent Trust Protocol) | Attestation, handshakes, and reputation | `agentmesh.trust.handshake`, `iatp.proto` |

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#2-quick-start--mcp-proxy-with-trust-gating) | Proxy an MCP server with trust scoring in 10 lines |
| [MCP Protocol Bridge](#3-mcp-protocol-bridge) | Trust-gated tool exposure, per-tool policies, filtering |
| [A2A Protocol Bridge](#4-a2a-protocol-bridge) | Agent Cards, task envelopes, skill-based routing |
| [IATP](#5-iatp--inter-agent-trust-protocol) | Ed25519 handshakes, attestation records, gRPC services |
| [Trusted Agent Cards](#6-trusted-agent-cards) | Cryptographically signed agent metadata |
| [Trust Gating](#7-trust-gating) | Threshold-based access control across protocols |
| [Multi-Protocol Orchestration](#8-multi-protocol-orchestration) | Agents communicating via different protocols |
| [CLI — agentmesh proxy](#9-cli--agentmesh-proxy) | Command-line MCP proxy with governance |
| [Cross-References](#10-cross-references) | Links to related tutorials |

---

## 2. Quick Start — MCP Proxy with Trust Gating

Wrap any MCP server with governance in five lines:

```python
from mcp_trust_proxy import TrustProxy, ToolPolicy

# Create a trust proxy with per-tool policies
proxy = TrustProxy(
    default_min_trust=300,
    tool_policies={
        "file_write": ToolPolicy(min_trust=800, required_capabilities=["fs_write"]),
        "shell_exec": ToolPolicy(blocked=True),
    },
)

# Agent requests tool access
result = proxy.authorize(
    agent_did="did:mesh:agent-1",
    agent_trust_score=600,
    agent_capabilities=["fs_read", "search"],
    tool_name="file_read",
)

print(result.allowed)       # True  — 600 ≥ 300 default threshold
print(result.reason)        # "Authorized"
print(result.trust_score)   # 600
```

---

## 3. MCP Protocol Bridge

The MCP bridge intercepts JSON-RPC 2.0 messages between an MCP client
(Claude Desktop, VS Code) and an MCP tool server, enforcing policies on
every `tools/call` request.

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  MCP Client  │ ──► │  AgentMesh      │ ──► │  MCP Server  │
│  (Claude,    │ ◄── │  Trust Proxy    │ ◄── │  (filesystem,│
│   VS Code)   │     │                 │     │   database)  │
└──────────────┘     └─────────────────┘     └──────────────┘
                       ● Policy check      ● Rate limiting
                       ● Trust score gate  ● Audit logging
```

### 3.1 TrustProxy — Middleware for Any MCP Server

`TrustProxy` works as middleware without importing the MCP SDK:

```python
from mcp_trust_proxy import TrustProxy, ToolPolicy

proxy = TrustProxy(
    default_min_trust=100, require_did=True,
    blocked_dids=["did:mesh:compromised-agent"],
)
proxy.set_tool_policy("database_query", ToolPolicy(
    min_trust=500, required_capabilities=["db_read"], max_calls_per_minute=30,
))
proxy.set_tool_policy("shell_exec", ToolPolicy(blocked=True))
```

### 3.2 Authorization Pipeline

`TrustProxy.authorize()` runs six checks in order:

| # | Check | Example Failure |
|---|-------|----------------|
| 1 | Agent DID present | `"Agent DID is required"` |
| 2 | DID not blocked | `"Agent {did} is blocked"` |
| 3 | Tool not blocked | `"Tool '{name}' is blocked by policy"` |
| 4 | Trust ≥ threshold | `"Trust score {n} below minimum {m}"` |
| 5 | Capabilities present | `"Missing capabilities: [...]"` |
| 6 | Rate limit OK | `"Rate limit exceeded ({n}/min)"` |

```python
result = proxy.authorize(
    agent_did="did:mesh:data-agent", agent_trust_score=750,
    agent_capabilities=["db_read", "search"], tool_name="database_query",
)
if not result.allowed:
    return {"jsonrpc": "2.0", "error": {"code": -32001, "message": result.reason}}
```

### 3.3 Audit Trail

Every authorization decision is logged:

```python
for entry in proxy.get_audit_log():
    print(f"{entry.tool_name}: {'✅' if entry.allowed else '❌'} "
          f"(agent={entry.agent_did}, trust={entry.trust_score})")

stats = proxy.get_stats()
# {"total_requests": 142, "allowed": 130, "denied": 12, ...}
```

### 3.4 MCP Governance Policy (YAML)

The `MCPProxy` CLI loads YAML governance policies:

```yaml
policies:
  - id: mcp-claude-desktop
    rules:
      - id: allow-reads
        action: allow
        conditions: ["tool in ['read_file', 'search_files']"]
      - id: approve-writes
        action: require_approval
        conditions: ["tool in ['write_file', 'execute_command']"]
      - id: block-destructive
        action: deny
        conditions: ["tool in ['delete_file', 'shell_exec']"]
    trust: {min_score: 600, score_penalty_on_deny: 10}
    audit: {enabled: true, format: cloudevents}
```

---

## 4. A2A Protocol Bridge

A2A (Agent-to-Agent) is an open standard for cross-framework agent
interoperability. The toolkit provides two integration layers:

- **`a2a_agentmesh`** — standalone bridge with `AgentCard`, `TaskEnvelope`, `TrustGate`
- **`agent_os.integrations.a2a_adapter`** — kernel-level governance

### 4.1 Agent Cards — Discovery via `/.well-known/agent.json`

An Agent Card is the A2A "business card" for discovery. AgentMesh extends
it with trust metadata via `x-agentmesh-*` fields:

```python
from a2a_agentmesh import AgentCard

card = AgentCard.from_identity(
    did="did:mesh:translator-01",
    name="TranslationAgent",
    description="Translates text between 40+ languages",
    capabilities=["translate", "detect_language", "summarize"],
    trust_score=800,
    organization="Linguatech",
)
print(card.to_json())
```

Output includes standard A2A fields plus AgentMesh extensions:

```json
{
  "name": "TranslationAgent",
  "skills": [{"id": "translate", "name": "Translate"}, ...],
  "authentication": {"schemes": ["iatp"]},
  "x-agentmesh-did": "did:mesh:translator-01",
  "x-agentmesh-trust-score": 800,
  "x-agentmesh-protocols": ["a2a/1.0", "iatp/1.0"]
}
```

```python
card.has_skill("translate")   # True
card.skill_ids()              # ["translate", "detect_language", "summarize"]
```

### 4.2 Task Envelopes — Trust-Verified Task Lifecycle

Tasks follow the A2A state machine: `submitted → working → complete/failed/canceled`.
AgentMesh embeds trust attestations in `x-agentmesh-trust`:

```python
from a2a_agentmesh import TaskEnvelope, TaskState

task = TaskEnvelope.create(
    skill_id="translate",
    source_did="did:mesh:orchestrator-01",
    target_did="did:mesh:translator-01",
    source_trust_score=750,
    input_text="Translate 'governance matters' to Spanish",
)

task.start()                                    # → WORKING
task.complete("La gobernanza importa")          # → COMPLETE
print(task.is_terminal)                         # True
# Invalid transitions raise ValueError
```

Serialize for JSON-RPC transport:

```python
wire_format = task.to_dict()
# Includes: id, status.state, skill_id, messages[], x-agentmesh-trust{}
received = TaskEnvelope.from_dict(wire_format)
```

### 4.3 Trust Gate — Policy Enforcement for A2A

The `TrustGate` evaluates incoming A2A tasks against configurable policies:

```python
from a2a_agentmesh import TrustGate, TrustPolicy, TaskEnvelope

gate = TrustGate(TrustPolicy(
    min_trust_score=500,
    max_requests_per_minute=30,
    blocked_dids=["did:mesh:banned-agent"],
    skill_trust_overrides={"admin_action": 900, "search": 200},
    require_did=True,
))

# Evaluate an incoming task
task = TaskEnvelope.create(
    skill_id="translate", source_did="did:mesh:caller",
    source_trust_score=600, input_text="Hello",
)
result = gate.evaluate(task)
print(result.allowed, result.reason)  # True, "Trust verified"

# Auto-fail denied tasks
low_trust = TaskEnvelope.create(
    skill_id="admin_action", source_did="did:mesh:newbie",
    source_trust_score=300, input_text="Delete all users",
)
result = gate.evaluate_and_gate(low_trust)
# low_trust.state == FAILED, low_trust.error contains denial reason
```

### 4.4 A2A Governance Adapter (Agent-OS)

For kernel-level governance, `A2AGovernanceAdapter` adds content filtering:

```python
from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

adapter = A2AGovernanceAdapter(
    allowed_skills=["search", "translate"],
    blocked_patterns=["DROP TABLE", "rm -rf"],
    min_trust_score=300,
)

result = adapter.evaluate_task({
    "skill_id": "search",
    "x-agentmesh-trust": {"source_did": "did:mesh:a", "source_trust_score": 500},
    "messages": [{"role": "user", "parts": [{"text": "Find weather"}]}],
})
print(result.allowed)  # True

# Blocked content
result = adapter.evaluate_task({
    "skill_id": "search",
    "x-agentmesh-trust": {"source_did": "did:mesh:b", "source_trust_score": 900},
    "messages": [{"role": "user", "parts": [{"text": "DROP TABLE users;"}]}],
})
print(result.allowed, result.reason)  # False, "Content matches blocked pattern..."
```

---

## 5. IATP — Inter-Agent Trust Protocol

IATP is the toolkit's native trust protocol providing cryptographic
handshakes, codebase attestation, and reputation tracking — defined in
Protocol Buffers for cross-language interoperability.

### 5.1 Trust Handshake (Ed25519 Challenge/Response)

`TrustHandshake` implements a four-step verification: challenge (random
nonce) → response (Ed25519 signature) → verification (registry check) →
result (trust level + capabilities).

```python
from agentmesh.identity import AgentIdentity, IdentityRegistry
from agentmesh.trust.handshake import TrustHandshake

registry = IdentityRegistry()
agent_a = AgentIdentity.create(name="Orchestrator", sponsor="ops@co.com",
    capabilities=["orchestrate"])
agent_b = AgentIdentity.create(name="DataAgent", sponsor="data@co.com",
    capabilities=["read:data", "query:db"])
registry.register(agent_a)
registry.register(agent_b)

handshake = TrustHandshake(
    agent_did=str(agent_a.did), identity=agent_a, registry=registry,
)
result = await handshake.initiate(
    peer_did=str(agent_b.did), protocol="iatp",
    required_trust_score=500, required_capabilities=["read:data"],
)

if result.verified:
    print(result.trust_level)     # "trusted"
    print(result.trust_score)     # 800
    print(result.capabilities)    # ["read:data", "query:db"]
    print(f"{result.latency_ms}ms")
```

Trust levels map from score ranges:

```
Ring 0 (≥900)  ████████████████████████████████████████  Verified Partner
Ring 1 (≥700)  ██████████████████████████████            Trusted
Ring 2 (≥400)  ████████████████████                      Standard
Ring 3 (<400)  ██████████                                Untrusted
               0    200    400    600    800    1000
```

### 5.2 Handshake Caching

Verified peers are cached (default: 15 minutes) to avoid repeated
cryptographic operations. Use `handshake.clear_cache()` to force
re-verification. Handshakes that exceed the timeout raise
`HandshakeTimeoutError`.

### 5.3 IATP Protocol Buffer Definitions

IATP is defined in Protocol Buffers (`agent-governance-python/agent-os/modules/iatp/proto/iatp.proto`).
Key messages:

| Message | Purpose |
|---------|---------|
| `CapabilityManifest` | Agent ID, trust level, capabilities, privacy contract |
| `AttestationRecord` | Codebase hash, config hash, signature, expiry |
| `HandshakeRequest/Response` | Manifest + attestation + nonce / session token |
| `ActionRequest/Response` | Action name, parameters, undo info |
| `ReputationEvent` | Event type, severity, score delta |

Three gRPC services: **`TrustProtocol`** (Handshake, ExecuteAction,
UndoAction, StreamActions), **`AttestationService`** (RequestAttestation,
VerifyAttestation), and **`ReputationService`** (GetReputation, ReportEvent,
StreamReputationUpdates).

Build stubs with `grpc_tools.protoc` (Python), `grpc_tools_node_protoc`
(Node.js), or `protoc --go_out` (Go).

### 5.4 Attestation and Privacy

Attestation records bind an agent's codebase to a cryptographic hash,
preventing tampering after deployment. The `AttestationRecord` includes
SHA-256 hashes of both code and config, plus a Control Plane signature.

IATP handshakes also include a `PrivacyContract` specifying data handling:
retention policy (ephemeral/temporary/permanent), storage location,
human review consent, and encryption requirements. Agents can reject
handshakes whose privacy terms don't meet their requirements.

---

## 6. Trusted Agent Cards

`TrustedAgentCard` extends A2A Agent Cards with Ed25519 cryptographic
signatures to prevent impersonation:

```python
from agentmesh.identity import AgentIdentity
from agentmesh.trust.cards import TrustedAgentCard, CardRegistry

identity = AgentIdentity.create(
    name="AnalyticsAgent", sponsor="data-team@company.com",
    capabilities=["analyze", "report", "visualize"],
)

# Create a signed card from identity
card = TrustedAgentCard.from_identity(identity)
print(card.agent_did)        # "did:mesh:..."
print(card.card_signature)   # Base64 Ed25519 signature

# Verify — anyone with public key can check
assert card.verify_signature()

# Tamper → verification fails
card.name = "MaliciousAgent"
assert not card.verify_signature()
```

The `CardRegistry` stores verified cards with capability-based discovery
and revocation list integration:

```python
registry = CardRegistry(cache_ttl_seconds=900)
registry.register(card)                             # Verifies signature first
translators = registry.find_by_capability("translate")  # Capability discovery
is_valid = registry.is_verified("did:mesh:agent-1")     # Cached + revocation check
```

---

## 7. Trust Gating

Trust gating is the core principle connecting all protocol bridges. Before
any cross-protocol communication proceeds, the initiator's trust score is
checked against a threshold.

### 7.1 TrustBridge — Peer Verification and Caching

`TrustBridge` manages peer trust with HMAC integrity protection:

```python
from agentmesh.trust.bridge import TrustBridge

bridge = TrustBridge(
    agent_did="did:mesh:my-agent", default_trust_threshold=700,
    identity=my_identity, registry=identity_registry,
)

# Verify peer (IATP handshake), result is HMAC-cached
result = await bridge.verify_peer(
    peer_did="did:mesh:remote-agent", protocol="iatp",
    required_trust_score=600, required_capabilities=["read:data"],
)

# Quick cached check (verifies HMAC integrity of stored record)
is_ok = await bridge.is_peer_trusted("did:mesh:remote-agent", required_score=600)
trusted = bridge.get_trusted_peers(min_score=800)
await bridge.revoke_peer_trust("did:mesh:compromised", reason="anomaly detected")
```

### 7.2 Trust Thresholds by Protocol

Different protocols can enforce different trust thresholds:

| Protocol | Typical Threshold | Use Case |
|----------|------------------|----------|
| MCP (read tools) | 300 | Low-risk data access |
| MCP (write tools) | 800 | Filesystem modifications |
| A2A (task delegation) | 500 | Standard inter-agent tasks |
| A2A (admin actions) | 900 | Privileged operations |
| IATP (handshake) | 700 | Default for peer verification |

---

## 8. Multi-Protocol Orchestration

The `ProtocolBridge` enables agents to communicate across protocols
with automatic message translation and trust verification:

```python
from agentmesh.trust.bridge import ProtocolBridge

bridge = ProtocolBridge(
    agent_did="did:mesh:orchestrator",
    identity=orchestrator_identity, registry=identity_registry,
)
print(bridge.supported_protocols)  # ["a2a", "mcp", "iatp", "acp"]
```

### 8.1 Cross-Protocol Message Translation

The bridge translates messages between A2A and MCP:

```python
# A2A → MCP: task_type → params.name, parameters → params.arguments
a2a_message = {"task_type": "file_analysis", "parameters": {"path": "/data/report.csv"}}
result = await bridge.send_message(
    peer_did="did:mesh:mcp-agent", message=a2a_message,
    source_protocol="a2a", target_protocol="mcp",
)
# Translated to: {"method": "tools/call", "params": {"name": "file_analysis", ...}}

# MCP → A2A: params.name → task_type, params.arguments → parameters
# IATP → *: IATP wraps any protocol (passthrough)
```

### 8.2 Verification Footers

The bridge appends verification footers proving governance was applied:

```python
verified = bridge.add_verification_footer(
    content="Analysis complete.", trust_score=850,
    agent_did="did:mesh:agent", metadata={"policy": "strict"},
)
# Appends: > 🔒 Verified by AgentMesh (Trust Score: 850/1000)
```

### 8.3 Multi-Agent Workflow

Combining all three protocols:

```python
from agentmesh.identity import AgentIdentity, IdentityRegistry
from a2a_agentmesh import TaskEnvelope, TrustGate, TrustPolicy
from mcp_trust_proxy import TrustProxy, ToolPolicy

# Identities
registry = IdentityRegistry()
orchestrator = AgentIdentity.create(name="Orchestrator", sponsor="ops@co.com",
    capabilities=["orchestrate"])
data_agent = AgentIdentity.create(name="DataAgent", sponsor="data@co.com",
    capabilities=["query:db"])
registry.register(orchestrator)
registry.register(data_agent)

# Gates
mcp_proxy = TrustProxy(default_min_trust=300, tool_policies={
    "query_db": ToolPolicy(min_trust=500, required_capabilities=["query:db"]),
})
a2a_gate = TrustGate(TrustPolicy(min_trust_score=400))

# Orchestrator → A2A → DataAgent → MCP → database tool
task = TaskEnvelope.create(skill_id="query:db",
    source_did=str(orchestrator.did), source_trust_score=850,
    input_text="SELECT count(*) FROM transactions WHERE amount > 10000")

if a2a_gate.evaluate(task).allowed:
    task.start()
    auth = mcp_proxy.authorize(agent_did=str(data_agent.did),
        agent_trust_score=800, agent_capabilities=["query:db"],
        tool_name="query_db")
    if auth.allowed:
        task.complete("1,247 high-value transactions")
```

---

## 9. CLI — `agentmesh proxy`

Start a transparent MCP proxy wrapping any MCP server with governance.

### 9.1 Basic Usage

```bash
# Proxy a filesystem MCP server with strict policy
agentmesh proxy --policy strict \
  --target npx --target -y \
  --target @modelcontextprotocol/server-filesystem --target /Users/me

# Proxy a Python MCP server with moderate policy, no footers
agentmesh proxy --policy moderate --no-footer \
  --target python --target my_mcp_server.py
```

### 9.2 CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target`, `-t` | Target MCP server command (repeat for args) | *required* |
| `--policy`, `-p` | Policy level: `strict`, `moderate`, `permissive` | `strict` |
| `--no-footer` | Disable verification footers in output | `false` |
| `--identity`, `-i` | Agent identity name | `mcp-proxy` |

### 9.3 Policy Levels

- **Strict** (default): Blocks writes/deletes, blocks `/etc` and `/root`, allows reads only
- **Moderate**: Warns on writes but allows them, blocks critical system paths
- **Permissive**: Allows all operations, logs everything for audit

### 9.4 Target Binary Allowlist

The proxy restricts which binaries can be spawned. Default:
`npx, node, python, python3, uvx, uv, echo, cat, test`.
Extend via `AGENTMESH_PROXY_ALLOWED_TARGETS=ruby,cargo,deno`.

### 9.5 How the Proxy Works

The `MCPProxy` class (in `agentmesh.cli.proxy`) sits between stdin/stdout,
intercepting JSON-RPC 2.0 messages. On every `tools/call`:

1. Parse JSON-RPC request (non-JSON messages are dropped)
2. Build policy context (`tool`, `path`)
3. Evaluate against `PolicyEngine`
4. **Blocked** → Return JSON-RPC error (code `-32001`) to client
5. **Allowed** → Forward to target, update trust score (+1)
6. **Response** → Optionally append verification footer
7. Log to `AuditLog`

---

## 10. Cross-References

| Tutorial | Relationship |
|----------|-------------|
| [Tutorial 02 — Trust and Identity](02-trust-and-identity.md) | Agent DIDs, Ed25519 keys, trust scoring — the foundation for all protocol bridges |
| [Tutorial 07 — MCP Security Gateway](07-mcp-security-gateway.md) | `MCPGateway` and `MCPSecurityScanner` — complementary MCP protection |
| [Tutorial 01 — Policy Engine](01-policy-engine.md) | YAML policies used by `MCPProxy` and `A2AGovernanceAdapter` |
| [Tutorial 04 — Audit and Compliance](04-audit-and-compliance.md) | Audit logging for cross-protocol interactions |
| [Tutorial 13 — Observability and Tracing](13-observability-and-tracing.md) | Distributed tracing context propagated via IATP `TracingContext` |

---

## Summary

| Concept | Key Class | What It Does |
|---------|-----------|-------------|
| MCP Trust Proxy | `TrustProxy` | Per-tool trust thresholds, capability checks, rate limiting |
| MCP CLI Proxy | `MCPProxy` | Transparent stdin/stdout proxy with policy enforcement |
| A2A Agent Card | `AgentCard` | A2A-compliant discovery with AgentMesh trust extensions |
| A2A Task Envelope | `TaskEnvelope` | Trust-verified task lifecycle with state machine |
| A2A Trust Gate | `TrustGate` | Policy enforcement for incoming A2A tasks |
| A2A Governance | `A2AGovernanceAdapter` | Kernel-level A2A governance with content filtering |
| IATP Handshake | `TrustHandshake` | Ed25519 challenge/response with registry verification |
| IATP Proto | `iatp.proto` | Cross-language gRPC services for trust, attestation, reputation |
| Trusted Agent Card | `TrustedAgentCard` | Cryptographically signed agent metadata card |
| Card Registry | `CardRegistry` | Discovery and verification of signed agent cards |
| Trust Bridge | `TrustBridge` | Peer verification with HMAC-protected caching |
| Protocol Bridge | `ProtocolBridge` | Cross-protocol message translation (A2A ↔ MCP ↔ IATP) |

**Next:** [Tutorial 18 — Compliance Verification](18-compliance-verification.md)
