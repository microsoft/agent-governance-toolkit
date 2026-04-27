# Agent Governance Toolkit v3.1.1

> [!IMPORTANT]
> **Public Preview** — All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA. For feedback, open an issue or contact
> agentgovtoolkit@microsoft.com.

## Highlights

### E2E Encrypted Agent Messaging (Signal Protocol)

AGT now provides **end-to-end encrypted channels** between agents using the
Signal protocol — the same cryptographic protocol that secures WhatsApp and
Signal Messenger, adapted for agent-to-agent communication.

```python
from agentmesh.encryption.bridge import EncryptedTrustBridge

bridge = EncryptedTrustBridge(agent_did="did:agentmesh:alice", key_manager=keys)
channel = await bridge.open_secure_channel("did:agentmesh:bob", bob_bundle)
ciphertext = channel.send(b"governed action request")
```

- **X3DH key agreement** using AGT's Ed25519 identity keys
- **Double Ratchet** with per-message forward secrecy and post-compromise security
- **ChaCha20-Poly1305** authenticated encryption
- **EncryptedTrustBridge** gates channels on successful trust handshake
- **61 tests** across 4 new modules
- **Zero new dependencies** — built on existing PyNaCl + cryptography

See [Tutorial 32 — E2E Encrypted Messaging](docs/tutorials/32-e2e-encrypted-messaging.md).

### GitHub Pages Documentation Site

Full documentation now available at **https://microsoft.github.io/agent-governance-toolkit/** — built with MkDocs Material, auto-deployed on every docs change.

### Security Hardening

- Resolved **all 106 open code scanning alerts**
- Added **BinSkim** binary security analysis for .NET DLLs
- Upgraded dependencies to address **6 Dependabot security vulnerabilities**
- Removed hardcoded credentials flagged by secret scanning

### Cross-Language SDK Parity

- **.NET**: MCP security namespace, kill switch, lifecycle management
- **Go**: MCP security, execution rings, lifecycle management
- **Rust**: Execution rings and lifecycle management

### CI/CD Improvements

- **Path filters** on 5 code-only workflows — docs-only PRs drop from ~14 checks to ~4
- **Concurrency groups** cancel stale duplicate runs
- **ESRP NuGet signing** fixed for cert-based authentication

## Breaking Changes

**None.** This is a backwards-compatible patch release.

## Upgrading

```bash
pip install --upgrade agent-governance-toolkit==3.1.1
```

For individual packages:

```bash
pip install --upgrade agent-os-kernel==3.1.1
pip install --upgrade agentmesh-platform==3.1.1
pip install --upgrade agent-hypervisor==3.1.1
pip install --upgrade agent-sre==3.1.1
```
