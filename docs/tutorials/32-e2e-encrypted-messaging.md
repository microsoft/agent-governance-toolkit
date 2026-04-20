<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 32 — E2E Encrypted Agent Messaging

> **Package:** `agentmesh-platform` · **Time:** 30 minutes · **Prerequisites:** Python 3.10+, [Tutorial 02](02-trust-and-identity.md)

---

## What You'll Learn

- Why AI agents need E2E encrypted channels (not just TLS)
- X3DH key agreement using AGT's Ed25519 identity keys
- Double Ratchet for per-message forward secrecy
- SecureChannel API for simple send/receive
- EncryptedTrustBridge: trust-gated encrypted sessions
- Pre-key management and session lifecycle

---

## Why E2E Encryption for Agents?

TLS protects data **in transit** between network hops. But in multi-agent
systems, messages often pass through intermediaries — relay servers, message
brokers, orchestration layers. TLS terminates at each hop, meaning
intermediaries can read the plaintext.

E2E encryption ensures that **only the two communicating agents** can read
the messages, regardless of how many hops the data traverses.

```
Without E2E:  Agent A ──TLS──► Relay ──TLS──► Agent B
              (relay can read plaintext)

With E2E:     Agent A ══E2E══════════════════► Agent B
              (relay sees only ciphertext)
```

AGT's E2E encryption uses the **Signal protocol** — the same protocol that
secures WhatsApp, Signal, and Google Messages — adapted for agent-to-agent
communication with AGT's DID-based identity system.

### Security Properties

| Property | What It Means |
|----------|--------------|
| **Confidentiality** | Only the two agents can decrypt messages |
| **Forward secrecy** | Compromising today's keys can't decrypt yesterday's messages |
| **Post-compromise security** | The ratchet heals — future messages are secure even after a key compromise |
| **Replay protection** | Each message key is single-use |
| **Identity binding** | Channels are bound to Ed25519 agent identities (DIDs) |

---

## Installation

```bash
pip install agentmesh-platform    # includes encryption module
```

All cryptographic operations use existing AGT dependencies — no new
packages required:
- **PyNaCl** (libsodium) — X25519 Diffie-Hellman, Ed25519 signatures
- **cryptography** — HKDF key derivation, ChaCha20-Poly1305 encryption

---

## 1. X3DH Key Agreement

X3DH (Extended Triple Diffie-Hellman) establishes a shared secret between
two agents who may never have communicated before. It uses AGT's existing
Ed25519 identity keys, converted to X25519 for the Diffie-Hellman
operations.

### How It Works

```
Alice (initiator)                          Bob (responder)
─────────────────                          ────────────────
Identity Key (IK)                          Identity Key (IK)
Ephemeral Key (EK) ←── generated           Signed Pre-Key (SPK)
                                           One-Time Pre-Key (OPK)

Alice computes:
  DH1 = DH(IK_alice, SPK_bob)
  DH2 = DH(EK_alice, IK_bob)
  DH3 = DH(EK_alice, SPK_bob)
  DH4 = DH(EK_alice, OPK_bob)       ← optional

Shared secret = HKDF(DH1 || DH2 || DH3 || DH4)
```

### Code Example

```python
from nacl.signing import SigningKey
from agentmesh.encryption.x3dh import X3DHKeyManager

# Create identity keys for two agents
alice_sk = SigningKey.generate()
bob_sk = SigningKey.generate()

alice_mgr = X3DHKeyManager.from_ed25519_keys(
    bytes(alice_sk) + bytes(alice_sk.verify_key),
    bytes(alice_sk.verify_key),
)
bob_mgr = X3DHKeyManager.from_ed25519_keys(
    bytes(bob_sk) + bytes(bob_sk.verify_key),
    bytes(bob_sk.verify_key),
)

# Bob publishes pre-keys
bob_mgr.generate_signed_pre_key()
bob_mgr.generate_one_time_pre_keys(10)
bob_bundle = bob_mgr.get_public_bundle(otk_id=0)

# Alice initiates X3DH
alice_result = alice_mgr.initiate(bob_bundle)
print(f"Shared secret: {alice_result.shared_secret.hex()[:16]}...")

# Bob responds (derives the same secret)
bob_result = bob_mgr.respond(
    peer_identity_key=alice_mgr.identity_key.public_key,
    ephemeral_public_key=alice_result.ephemeral_public_key,
    used_one_time_key_id=alice_result.used_one_time_key_id,
)

assert alice_result.shared_secret == bob_result.shared_secret  # ✅
```

### Pre-Key Management

Each agent publishes a **pre-key bundle** containing:
- **Identity key** — derived from the agent's Ed25519 DID key
- **Signed pre-key** — rotated periodically, signed by the identity key
- **One-time pre-keys** — consumed on use (each initiator gets a unique one)

```python
from agentmesh.encryption.x3dh import InMemoryPreKeyStore

store = InMemoryPreKeyStore()
store.store_bundle("did:mesh:bob", bob_bundle)

# Later, Alice retrieves Bob's bundle
bundle = store.get_bundle("did:mesh:bob")
```

> **Production:** Replace `InMemoryPreKeyStore` with a Redis or SQL
> implementation for multi-process deployments.

---

## 2. Double Ratchet

The Double Ratchet provides **per-message forward secrecy**. Each message
is encrypted with a unique key derived from two ratcheting chains:

- **Symmetric ratchet** — HMAC chain advances with every message
- **DH ratchet** — X25519 key exchange advances on each turn change

```
Alice sends 3 messages:     Keys: CK₀ → CK₁ → CK₂ (symmetric ratchet)
Bob replies:                DH ratchet step (new X25519 keys)
Alice sends again:          New chain, new keys (forward secrecy)
```

### Code Example

```python
from agentmesh.encryption.ratchet import DoubleRatchet

# Initialize from X3DH shared secret
alice_ratchet = DoubleRatchet.init_sender(
    shared_secret=alice_result.shared_secret,
    remote_dh_public=bob_bundle.signed_pre_key,
)
bob_ratchet = DoubleRatchet.init_receiver(
    shared_secret=bob_result.shared_secret,
    dh_key_pair=(
        bob_mgr.signed_pre_key.key_pair.private_key,
        bob_mgr.signed_pre_key.key_pair.public_key,
    ),
)

# Encrypt and decrypt
enc = alice_ratchet.encrypt(b"hello bob")
plaintext = bob_ratchet.decrypt(enc)
assert plaintext == b"hello bob"  # ✅

# Bidirectional — Bob replies
enc2 = bob_ratchet.encrypt(b"hello alice")
assert alice_ratchet.decrypt(enc2) == b"hello alice"  # ✅
```

### Out-of-Order Messages

The Double Ratchet caches skipped message keys, so messages delivered
out of order are decrypted correctly:

```python
enc0 = alice_ratchet.encrypt(b"msg-0")
enc1 = alice_ratchet.encrypt(b"msg-1")
enc2 = alice_ratchet.encrypt(b"msg-2")

# Deliver in reverse order — all decrypt correctly
assert bob_ratchet.decrypt(enc2) == b"msg-2"
assert bob_ratchet.decrypt(enc0) == b"msg-0"
assert bob_ratchet.decrypt(enc1) == b"msg-1"
```

### Session Persistence

Ratchet state is serializable for persistence across restarts:

```python
# Save
saved = alice_ratchet.state.to_dict()

# Restore
from agentmesh.encryption.ratchet import DoubleRatchet, RatchetState
restored = DoubleRatchet(RatchetState.from_dict(saved))
```

---

## 3. SecureChannel API

`SecureChannel` combines X3DH + Double Ratchet into a simple high-level
API:

```python
from agentmesh.encryption.channel import SecureChannel

# Alice creates a channel
alice_ch, establishment = SecureChannel.create_sender(
    alice_mgr, bob_bundle, associated_data=b"did:mesh:alice|did:mesh:bob"
)

# Bob accepts (using the establishment data sent out-of-band)
bob_ch = SecureChannel.create_receiver(
    bob_mgr, establishment, associated_data=b"did:mesh:alice|did:mesh:bob"
)

# Exchange encrypted messages
enc = alice_ch.send(b"governed action request")
assert bob_ch.receive(enc) == b"governed action request"

enc = bob_ch.send(b"action approved")
assert alice_ch.receive(enc) == b"action approved"

# Clean up — zeroes key material
alice_ch.close()
bob_ch.close()
```

### API Reference

| Method | Description |
|--------|-------------|
| `SecureChannel.create_sender(mgr, bundle, ad)` | Create channel as initiator |
| `SecureChannel.create_receiver(mgr, establishment, ad)` | Accept channel as responder |
| `channel.send(plaintext)` | Encrypt and return `EncryptedMessage` |
| `channel.receive(message)` | Decrypt and return plaintext |
| `channel.close()` | Close channel, zero key material |
| `channel.is_closed` | Whether the channel has been closed |
| `channel.message_count` | Total messages sent + received |

---

## 4. EncryptedTrustBridge

The `EncryptedTrustBridge` is the recommended way to use E2E encryption
in production. It **gates encrypted channels on successful trust
verification** — peers that fail the handshake never reach the key
exchange step.

```python
from agentmesh.encryption.bridge import EncryptedTrustBridge

# Alice's bridge requires trust score ≥ 700
alice_bridge = EncryptedTrustBridge(
    agent_did="did:mesh:alice",
    key_manager=alice_mgr,
    min_trust_score=700,
)

# Bob publishes pre-keys
bob_bridge = EncryptedTrustBridge(
    agent_did="did:mesh:bob",
    key_manager=bob_mgr,
)
bob_bundle = bob_bridge.publish_prekey_bundle()

# Alice opens channel (trust verification → X3DH → Double Ratchet)
channel = await alice_bridge.open_secure_channel(
    "did:mesh:bob", bob_bundle
)

# Bob accepts
bob_channel = bob_bridge.accept_secure_channel(
    "did:mesh:alice",
    alice_bridge.get_session("did:mesh:bob").establishment,
)

# Exchange messages
enc = channel.send(b"transfer $1000 to account X")
assert bob_channel.receive(enc) == b"transfer $1000 to account X"
```

### Session Management

```python
# List active sessions
sessions = alice_bridge.active_sessions
print(f"Active: {list(sessions.keys())}")

# Close one session
alice_bridge.close_session("did:mesh:bob")

# Close all sessions (e.g., on agent shutdown)
alice_bridge.close_all_sessions()
```

### Flow Diagram

```
Alice                              Bob
  │                                 │
  ├── TrustHandshake ──────────────►│
  │   (Ed25519 challenge-response)  │
  │◄── trust_score=850 ────────────┤
  │                                 │
  │   Trust verified ✅              │
  │                                 │
  ├── X3DH initiate ──────────────►│
  │   (ephemeral key + OTK)         │
  │◄── X3DH respond ──────────────┤
  │   (shared secret derived)       │
  │                                 │
  │   Double Ratchet initialized    │
  │                                 │
  ├══ Encrypted message ══════════►│
  │◄═ Encrypted reply ════════════┤
  │                                 │
```

---

## 5. Choosing Your Encryption Depth

| Scenario | Module | When to Use |
|----------|--------|-------------|
| **Just need shared secret** | `X3DHKeyManager` | Custom protocols, one-time exchanges |
| **Need encrypted messages** | `DoubleRatchet` | Direct agent-to-agent messaging |
| **Want a simple API** | `SecureChannel` | Most use cases |
| **Production with trust gates** | `EncryptedTrustBridge` | Recommended for governed systems |

---

## Cross-Reference

| Resource | Description |
|----------|-------------|
| [Tutorial 02 — Trust & Identity](02-trust-and-identity.md) | Ed25519 credentials, DIDs, trust scoring |
| [Tutorial 07 — MCP Security Gateway](07-mcp-security-gateway.md) | Tool call governance |
| [Tutorial 16 — Protocol Bridges](16-protocol-bridges.md) | A2A, MCP, IATP communication |
| [Tutorial 31 — MCP Governance End-to-End](31-mcp-governance-end-to-end.md) | MCP message signing |
| [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/) | X3DH reference (CC0) |
| [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/) | Double Ratchet reference (CC0) |

---

## Summary

You now know how to:

1. **Establish shared secrets** between agents using X3DH key agreement
2. **Encrypt messages** with per-message forward secrecy via the Double Ratchet
3. **Use the SecureChannel API** for simple send/receive encryption
4. **Gate encrypted channels on trust** with EncryptedTrustBridge
5. **Manage pre-keys and sessions** for production deployments

Combined with AGT's policy engine, audit logging, and trust scoring,
E2E encryption completes the security stack for governed multi-agent
systems.
