# OWASP GenAI — Community Tool Submission

## Tool Name

Agent Governance Stack (Agent OS + AgentMesh + Agent SRE + Agent Runtime)

## Category

AI Agent Security & Governance Framework

## Description

Open-source framework providing runtime governance for autonomous AI agents.
Covers 10/10 OWASP Agentic Security Top 10 categories with full technical implementations.
Sub-millisecond policy enforcement (<0.1ms p99), 1,680+ tests, integrations with
12+ LLM frameworks (LangChain, CrewAI, OpenAI, Anthropic, AutoGen, SemanticKernel, etc.).

## OWASP Agentic Security Top 10 Coverage

### ASI01 — Agent Goal Hijack

- **PromptInjectionDetector**: 7-strategy defense (direct override, delimiter attacks, encoding attacks, role-play/jailbreak, context manipulation, canary leak, multi-turn escalation)
- **MCPSecurityScanner**: Tool poisoning defense — detects hidden instructions in MCP tool descriptions (zero-width unicode, markdown comments, base64-encoded payloads)
- **SemanticPolicyEngine**: Intent classification (9 categories including DATA_EXFILTRATION, PRIVILEGE_ESCALATION) with configurable confidence thresholds
- **LlamaFirewall integration**: Defense-in-depth chaining with external guardrail frameworks

### ASI02 — Tool Misuse & Exploitation

- **MCPSecurityScanner**: Rug pull detection via SHA-256 tool fingerprinting, cross-server impersonation detection (Levenshtein distance), schema abuse detection
- **GovernancePolicy.allowed_tools**: Whitelist-based tool access control
- **PolicyInterceptor**: Runtime interception of all tool calls with pre/post hooks
- **ExecutionSandbox**: Resource-limited execution with AST-based static analysis

### ASI03 — Identity & Privilege Abuse

- **AgentMesh DID-based identity**: `did:mesh:<unique-id>` format with Ed25519 keypairs
- **TrustRoot hierarchy**: Deterministic (non-LLM) policy authority with max escalation depth
- **SPIFFE integration**: mTLS workload identity via SPIFFEIdentity → SVID issuance
- **RBAC module**: Role-based access control with capability grants
- **Agent Runtime Execution Rings**: 4-tier privilege model (Ring 0–3) based on trust scores

### ASI04 — Agentic Supply Chain

- **MCPSecurityScanner**: Tool fingerprinting with `ToolFingerprint` (description_hash, schema_hash, version tracking)
- **Cross-server attack detection**: Typosquatting via Levenshtein distance, impersonation detection
- **MCP security scanner CLI**: `mcp-scan scan <config>` for auditing MCP server configurations
- **CVE coverage**: Addresses patterns from CVE-2026-25536, CVE-2026-23744, CVE-2025-68145

### ASI05 — Unexpected Code Execution

- **ExecutionSandbox**: AST-based security visitor blocks dangerous patterns
  - Blocked modules: subprocess, os, shutil, socket, ctypes, importlib
  - Blocked builtins: exec, eval, compile, \_\_import\_\_
- **SandboxConfig**: Configurable max_memory_mb, max_cpu_seconds, allowed_paths
- **SemanticPolicyEngine**: CODE_EXECUTION intent detection with deny policies
- **Content filtering**: blocked_patterns in GovernancePolicy

### ASI06 — Memory & Context Poisoning

- **MemoryGuard**: SHA-256 per-entry integrity verification
  - Injection pattern scanning on every write
  - Unicode manipulation detection
  - Code injection detection
  - Audit trail with timestamp and source for every memory operation
- **AlertType coverage**: INJECTION_PATTERN, CODE_INJECTION, INTEGRITY_VIOLATION, UNICODE_MANIPULATION, EXCESSIVE_SPECIAL_CHARS

### ASI07 — Insecure Inter-Agent Communications

- **AgentMesh TrustHandshake**: Nonce-based challenge/response authentication
- **Trust score propagation**: 5-dimension scoring (competence, integrity, availability, predictability, transparency)
- **TrustBridge**: Protocol adapters for A2A, MCP, IATP, AI Card protocols
- **gRPC + WebSocket transports**: Encrypted channels with heartbeat/keepalive
- **AuditChain**: Hash-chain audit logs for immutable compliance tracking
- **OPA integration**: Rego-based policy evaluation for inter-agent governance

### ASI08 — Cascading Failures

- **CircuitBreaker**: CLOSED → OPEN → HALF_OPEN state machine with configurable failure_threshold and reset_timeout
- **ChaosEngine**: Fault injection experiments (latency, error, timeout, adversarial)
- **ChaosLibrary**: Pre-built templates (tool-timeout, error-storm, cascading-failure)
- **Agent SRE IncidentDetector**: Signal correlation (SLO_BREACH, ERROR_BUDGET_EXHAUSTED, COST_ANOMALY, POLICY_VIOLATION)
- **ErrorBudget**: Burn rate alerts across multiple time windows (1h, 6h, 24h, 7d, 30d)

### ASI09 — Human-Agent Trust Exploitation

- **require_human_approval gates**: MCPGateway with approval workflow (PENDING/APPROVED/REJECTED)
- **Agent Runtime consensus**: Ring 1 operations require human consensus; Ring 0 requires SRE witness
- **GovernanceLogger**: Structured JSON audit trail for every policy decision
- **KillSwitch**: Immediate agent termination with reasons (behavioral drift, rate limit, ring breach, manual)
- **HumanSponsor / SponsorRegistry**: Accountability through human sponsorship of agent identities

### ASI10 — Rogue Agents

- **Agent SRE AnomalyDetector**: Behavioral anomaly detection (latency spikes, throughput drops, unusual tool sequences, resource exhaustion)
- **SLO engine**: Continuous compliance monitoring with error budget tracking
- **OpenTelemetry export**: TraceExporter + MetricsExporter for full observability
- **Agent Runtime RingEnforcer**: Trust-score-based demotion; automatic sandbox for untrusted agents
- **QuarantineManager**: Agent isolation with forensic data preservation
- **CostGuard**: Budget enforcement (throttle at 85%, kill at 95%)

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Agent Runtime                   │
│  Kill Switch · Execution Rings · Saga Rollback  │
├─────────────────────────────────────────────────┤
│                   Agent SRE                     │
│  SLO Engine · Anomaly Detection · Chaos Engine  │
├─────────────────────────────────────────────────┤
│                  AgentMesh                      │
│  DID Identity · Trust Handshake · SPIFFE · OPA  │
├─────────────────────────────────────────────────┤
│                   Agent OS                      │
│  Policy Engine · Sandbox · MemoryGuard · MCP    │
└─────────────────────────────────────────────────┘
```

## Links

- **GitHub (Agent OS)**: https://github.com/microsoft/agent-governance-toolkit
- **GitHub (AgentMesh)**: https://github.com/microsoft/agent-governance-toolkit
- **GitHub (Agent SRE)**: https://github.com/microsoft/agent-governance-toolkit
- **GitHub (Agent Runtime)**: https://github.com/microsoft/agent-governance-toolkit
- **Governance Docs**: https://github.com/microsoft/agent-governance-toolkit
- **OWASP Mapping**: https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/owasp-agentic-top10-mapping.md

## Maintainers

- Microsoft Corporation (Microsoft)

## License

MIT
