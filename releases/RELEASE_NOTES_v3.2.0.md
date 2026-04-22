# Agent Governance Toolkit v3.2.0

> [!IMPORTANT]
> **Public Preview** — All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA. For feedback, open an issue or contact
> agentgovtoolkit@microsoft.com.

## Highlights

### E2E Encrypted Agent Messaging — Now in Python AND TypeScript

v3.1.1 introduced Signal Protocol encryption for Python. v3.2.0 extends full
parity to the **TypeScript SDK** and adds relay-based transport:

- **SecureChannel** high-level API in both languages
- **EncryptedTrustBridge** — trust-gated encrypted sessions
- **MeshClient** — relay transport with plaintext peer compatibility, KNOCK pending queue, `wsFactory` hook
- **81 encryption tests** across both SDKs (up from 61 in v3.1.1)

### AgentMesh Wire Protocol v1.0

Published the formal protocol specification (`docs/specs/AGENTMESH-WIRE-1.0.md`):

- Envelope format with versioned headers
- Cipher suite negotiation (ChaCha20-Poly1305, AES-256-GCM)
- KNOCK intent protocol for connection establishment
- Registry API contract (8 endpoints)
- Relay semantics (store-and-forward, TTL, heartbeat)
- Authentication model (Ed25519 + Entra Agent ID bridge)
- Protocol versioning and backwards compatibility guarantees

Clean-room design with full IP and prior-art documentation.

### First-Party Registry + Relay Services

Two new backend services for agent discovery and offline messaging:

**Registry Service**
- Agent registration with DID + pre-key bundles
- Atomic one-time pre-key (OPK) consumption
- Discovery by DID, name, or capability
- Presence tracking (online/offline/away)
- Reputation score aggregation

**Relay Service**
- WebSocket store-and-forward messaging
- 72-hour TTL offline inbox
- Heartbeat-based connection management
- KNOCK routing for connection intent
- Ciphertext-only storage (relay cannot read message content)

### Graph API Group Membership Sync (Entra Agent ID)

New `entra_graph.py` module for Microsoft Graph API integration:

```python
from agentmesh.identity.entra_graph import EntraGraphClient

client = EntraGraphClient(access_token=token)
groups = client.get_group_memberships("service-principal-id")

# Sync to AGT capabilities
caps = registry.sync_group_memberships(
    agent_did=identity.did,
    graph_client=client,
    group_scope_map={"group-id": ["read:data", "write:reports"]},
)
```

- `EntraGraphClient` — stdlib-only Graph API client with pagination
- `sync_group_memberships()` on `EntraAgentRegistry` — maps Entra groups to AGT capabilities
- `validate_bridge_configuration()` — checks Agent365 compatibility
- 26 new tests

### Container Images Published to GHCR

All component images now published to GitHub Container Registry:

| Component | Image | Port |
|-----------|-------|------|
| Trust Engine | `ghcr.io/microsoft/agentmesh/trust-engine:0.3.0` | 8443 |
| Policy Server | `ghcr.io/microsoft/agentmesh/policy-server:0.3.0` | 8444 |
| Audit Collector | `ghcr.io/microsoft/agentmesh/audit-collector:0.3.0` | 8445 |
| API Gateway | `ghcr.io/microsoft/agentmesh/api-gateway:0.3.0` | 8446 |
| Governance Sidecar | `ghcr.io/microsoft/agentmesh/governance-sidecar:0.3.0` | 8081 |

- Multi-arch: `linux/amd64` + `linux/arm64`
- SLSA build provenance attestation
- `publish-containers.yml` workflow for automated builds on release

### GitHub Pages Documentation Site

69 pages now served at https://microsoft.github.io/agent-governance-toolkit:

- 10 package documentation pages
- 33 tutorials (including 6 new: tutorials 28–33)
- 6 ADRs (including ADR-0005 Liveness Attestation, ADR-0006 Constitutional Constraints)
- 4 security pages (threat model, OWASP compliance, scanning, tenant isolation)
- 5 reference pages (benchmarks, comparison, NIST RFI mapping, contributing, changelog)
- 4 deployment guides (Azure, Container Apps, Foundry Agent Service, OpenClaw sidecar)
- i18n: English, Japanese (日本語), Chinese (简体中文)

### Go SDK Reorganization

Moved Go SDK to top-level `agent-governance-golang/` directory per community feedback (#1198):

```go
import agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"
```

This improves Go module proxy resolution and aligns with Go ecosystem conventions.

### New Crypto Libraries (TypeScript)

- `@noble/curves` — X25519, Ed25519 (MIT, audited)
- `@noble/ciphers` — ChaCha20-Poly1305 (MIT, audited)
- `@noble/hashes` — HKDF-SHA256, HMAC (MIT, audited)

## Security

- Fixed 6 Dependabot vulnerabilities: python-multipart (DoS), pytest (tmpdir), langchain-core (SSRF + path traversal + f-string), tsup (DOM clobbering)
- Resolved CodeQL syntax errors in `demo.py` and `deploy.js`
- Removed hardcoded credentials from 7 files (RabbitMQ default password, fake API keys, private key templates, connection strings)
- Dismissed rand 0.8.5 Dependabot alert as not applicable (vuln affects 0.9.x API only)
- Added attribution & prior art policy to PR template, CONTRIBUTING.md, and copilot-instructions.md

## Community

- **ryanzhang-oss** — Go SDK reorganization (#1285), Dockerfile fix proposals
- **lawcontinue** — Chaos testing tutorial, ISO 42001 mapping, Windows UTF-8 fixes, ADR-0006, workshop content
- **tomjwxf** — Tutorial 33 (offline verifiable receipts), physical attestation examples, GitHub Pages docs site
- **zeel2104** — Architecture deep dive video series
- **willamhou** — Signet attestation layer examples
- **jackbatzner** — Governance wording alignment, contributor routing guidance

## Install / Upgrade

```bash
# Python
pip install --upgrade agent-governance-toolkit[full]==3.2.0

# TypeScript / Node.js
npm install @microsoft/agentmesh-sdk@3.2.0

# .NET
dotnet add package Microsoft.AgentGovernance --version 3.2.0

# Rust
cargo add agentmesh@3.2.0

# Go
go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang@v3.2.0

# Container images
docker pull ghcr.io/microsoft/agentmesh/governance-sidecar:0.3.0
```

**No breaking changes.** Backwards-compatible with v3.1.x.

## What's Next

- **GA at Microsoft Build** (May 2026) — pending session confirmation
- **Confidential computing** — TEE-bound agent keys with Azure Confidential Computing (proposal from Pawan Khandavilli)
- **Lightweight OS sandboxing** — nono integration for kernel-enforced Execution Rings (#748)
- **Oracle Agent Spec** — governance controls extension for Open Agent Specification
- **Cisco AI Defense** — complementary model-layer + action-layer security architecture

## Full Changelog

https://github.com/microsoft/agent-governance-toolkit/compare/v3.1.1...v3.2.0
