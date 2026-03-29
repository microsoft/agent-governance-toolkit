# Nexus Trust Exchange

**Agent Trust Exchange — Decentralized registry and communication board for AI agents.**

> 🛡️ **SECURE IMPLEMENTATION** — This module implements production-grade **Ed25519 cryptographic signature verification** for all agent operations.

## Overview

Nexus provides a decentralized trust exchange layer for AI agent ecosystems. It enables agents to:

- **Register** capabilities and identity with verifiable Ed25519 signatures
- **Exchange** trust attestations with other agents using IATP
- **Arbitrate** disputes through a cryptographic escrow/arbiter system
- **Build reputation** via a weighted reputation graph and "viral trust" scores

## Installation

```bash
pip install nexus-trust-exchange
```

## Components

| Module | Purpose |
|--------|---------|
| `registry.py` | Agent registration and capability discovery with signature enforcement |
| `crypto.py` | Ed25519 signing, verification, and canonical payload generation |
| `client.py` | Client SDK for interacting with the exchange |
| `arbiter.py` | Trust dispute resolution and task validation |
| `escrow.py` | Conditional trust escrow with signed receipts |
| `dmz.py` | Demilitarized zone for untrusted agent interaction |
| `reputation.py` | Reputation scoring and viral trust graph |
| `schemas/` | Pydantic models for all exchange messages |

## Quick Start

```python
from nexus.registry import AgentRegistry
from nexus.schemas.manifest import AgentManifest, AgentIdentity
from nexus import crypto

# 1. Initialize Registry
registry = AgentRegistry()

# 2. Setup Agent Identity
# You must have a valid Ed25519 public key (format: 'ed25519:<base64>')
public_key = "ed25519:YOUR_BASE64_PUBLIC_KEY"
manifest = AgentManifest(
    identity=AgentIdentity(
        did="did:mesh:agent-001",
        verification_key=public_key,
        owner_id="org-acme"
    ),
    capabilities=["code-review", "security-audit"]
)

# 3. Sign the Manifest (using your private key)
signature = crypto.sign_data(private_key, manifest)

# 4. Register
await registry.register(manifest=manifest, signature=signature)
```

## Security & Signatures

Nexus uses **Ed25519** signatures to prevent ID spoofing and unauthorized registration. 

- **Canonicalization**: Payloads are deterministic (keys sorted, no whitespace) via `crypto.canonical_payload`.
- **Legacy Support**: Agents registered before **2025-01-01** are treated as "Legacy" and can bypass signature checks to ensure backward compatibility during the transition period.

## Part of Agent-OS

This module is part of the [Agent-OS](https://github.com/microsoft/agent-governance-toolkit) ecosystem. Install the full stack:

```bash
pip install agent-os-kernel
```

## License

MIT
