# Changelog

All notable changes to AgentMesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha.1] - 2026-02-01

### Added

#### Layer 1: Identity & Zero-Trust Core
- `AgentIdentity` - First-class agent identity with Ed25519 cryptographic keys
- `AgentDID` - Decentralized identifiers for agents
- `ScopeChain` - Scope chains for scope narrowing
- `HumanSponsor` - Human sponsor accountability for every agent
- `Credential` - Ephemeral credentials with 15-minute default TTL
- `CredentialManager` - Automatic credential rotation and revocation
- `RiskScorer` - Continuous risk scoring updated every 30 seconds
- `SPIFFEIdentity` - SPIFFE/SVID workload identity for mTLS

#### Layer 2: Trust & Protocol Bridge
- `TrustBridge` - Unified trust layer across A2A, MCP, IATP, ACP
- `A2AAdapter` - Google A2A protocol support (Agent Card, task lifecycle)
- `MCPAdapter` - Anthropic MCP protocol support (tool registration, resource binding)
- `TrustHandshake` - IATP trust handshakes with <200ms target
- `CapabilityScope` - Capability-scoped credential issuance
- `CapabilityRegistry` - Resource and action-level capability control

#### Layer 3: Governance & Compliance Plane
- `PolicyEngine` - Declarative policy engine (YAML/JSON) with <5ms evaluation
- `Policy` and `PolicyRule` - Composable policy definitions
- `ComplianceEngine` - Automated compliance mapping
  - EU AI Act
  - SOC 2
  - HIPAA
  - GDPR
- `AuditLog` - Comprehensive audit logging
- `ShadowMode` - Pre-production red-teaming with <2% divergence target

#### Layer 4: Reward & Learning Engine
- `RewardEngine` - Behavioral reward scoring
- `TrustScore` - Per-agent trust scores (0-1000 scale)

#### CLI
- `agentmesh init` - Scaffold a governed agent in 30 seconds
- `agentmesh register` - Register agent with AgentMesh CA
- `agentmesh status` - View agent status and trust score breakdown
- `agentmesh policy` - Load and validate policy files
- `agentmesh audit` - View tamper-evident audit logs

### Dependencies
- Requires `agent-os[nexus,iatp]>=1.2.0` for IATP protocol and Nexus integration
- Python 3.11+ required

### Notes
- This is an alpha release for early adopters and design partners
- API may change before 1.0.0 stable release
- Not recommended for production use without consulting with maintainers
