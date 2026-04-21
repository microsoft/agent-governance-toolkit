<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AgentMesh Wire Protocol — Version 1.0

> **Status:** Draft · **Date:** 2026-04-21 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the wire protocol for E2E encrypted agent-to-agent
> messaging in the Agent Governance Toolkit. All SDK implementations (Python,
> TypeScript, Rust, .NET, Go) MUST conform to this specification.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Principles](#2-design-principles)
3. [Standards Foundation](#3-standards-foundation)
4. [Agent Identity](#4-agent-identity)
5. [Cryptographic Primitives](#5-cryptographic-primitives)
6. [Key Management](#6-key-management)
7. [X3DH Key Agreement](#7-x3dh-key-agreement)
8. [Double Ratchet](#8-double-ratchet)
9. [Message Envelope](#9-message-envelope)
10. [KNOCK Intent Protocol](#10-knock-intent-protocol)
11. [Registry API](#11-registry-api)
12. [Relay Service](#12-relay-service)
13. [Authentication](#13-authentication)
14. [Governance Integration](#14-governance-integration)
15. [Protocol Versioning](#15-protocol-versioning)
16. [Security Considerations](#16-security-considerations)
17. [Test Vectors](#17-test-vectors)
18. [References](#18-references)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the wire protocol for secure, authenticated,
end-to-end encrypted messaging between AI agents in the AgentMesh network.
The protocol provides:

- **Confidentiality** — only the two communicating agents can decrypt messages
- **Forward secrecy** — compromising current keys cannot decrypt past messages
- **Post-compromise security** — the ratchet heals after key compromise
- **Authentication** — messages are cryptographically bound to agent identities
- **Replay protection** — each message key is single-use
- **Offline delivery** — messages persist for offline agents via store-and-forward

### 1.2 Scope

This specification covers pair-wise (1:1) agent-to-agent messaging. Group
messaging (1:N) is out of scope for v1.0 and reserved for a future version
using MLS (RFC 9420).

### 1.3 Relationship to AGT Governance

This protocol defines the **transport layer**. AGT's governance layer
(policy engine, trust scoring, audit logging) operates **around** the
transport — evaluating whether a message should be sent or received before
the transport layer encrypts or decrypts it. Governance and transport are
deliberately separated so each can evolve independently.

```
┌─────────────────────────────────┐
│  AGT Governance Layer           │
│  Policy ─► Trust ─► Audit       │
└──────────────┬──────────────────┘
               │ allow / deny
┌──────────────▼──────────────────┐
│  AgentMesh Wire Protocol v1.0   │
│  X3DH ─► Ratchet ─► Envelope   │
└──────────────┬──────────────────┘
               │ ciphertext
┌──────────────▼──────────────────┐
│  Transport (WebSocket / gRPC)   │
└─────────────────────────────────┘
```

---

## 2. Design Principles

1. **Standards first.** Every cryptographic operation references a published
   RFC or specification. No custom crypto.
2. **One identity, everywhere.** A single agent identity format across all
   SDKs and services.
3. **Crypto in every language.** The protocol MUST be implementable in
   Python, TypeScript, Rust, .NET, and Go using audited libraries.
4. **Governance-separable.** Governance decisions are made before the
   transport layer acts — the transport never makes policy decisions.
5. **Relay is a service, not a feature.** Store-and-forward is a deployable
   service, not embedded in the SDK.
6. **Protocol versioning.** Every frame carries a version field. Future
   versions (including MLS group support) can be negotiated.

---

## 3. Standards Foundation

| Component | Standard | Reference |
|-----------|----------|-----------|
| Key agreement | X3DH | [Signal X3DH Spec](https://signal.org/docs/specifications/x3dh/) (CC0) |
| Session encryption | Double Ratchet | [Signal Double Ratchet Spec](https://signal.org/docs/specifications/doubleratchet/) (CC0) |
| Diffie-Hellman | X25519 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| Key derivation | HKDF-SHA256 | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| Symmetric encryption | ChaCha20-Poly1305 | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| Signatures | Ed25519 | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |
| Identity | DID | [W3C DID Core](https://www.w3.org/TR/did-core/) |
| Future group messaging | MLS | [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) |

### 3.1 Why Signal Protocol over MLS for v1

| Criterion | Signal Protocol | MLS (RFC 9420) |
|-----------|----------------|----------------|
| Pair-wise messaging | Native | Supported (group of 2) |
| Group messaging | N×(N-1)/2 sessions | Native tree ratchet |
| Implementation complexity | Moderate | High |
| Existing AGT implementation | Python (61 tests) | None |
| Ecosystem adoption | WhatsApp, Signal, Google Messages | Cisco Webex, Wire (emerging) |
| Specification maturity | 10+ years | RFC published 2023 |

Signal Protocol is chosen for v1 because AGT already has a working Python
implementation, the agent-to-agent use case is primarily pair-wise, and the
implementation burden across 5 languages is manageable. MLS is reserved for
v2 group messaging via the protocol version negotiation mechanism defined
in [Section 15](#15-protocol-versioning).

---

## 4. Agent Identity

### 4.1 Identity Format

All agents are identified by a **DID** (Decentralized Identifier) following
the W3C DID Core specification:

```
did:agentmesh:<fingerprint>
```

Where `<fingerprint>` is:

```
fingerprint = base58btc(sha256(ed25519_public_key)[0:20])
```

This is a **20-byte truncated SHA-256 hash** of the agent's Ed25519 public
key, encoded in base58btc (Bitcoin alphabet).

**Properties:**
- Self-verifying: anyone with the public key can recompute the fingerprint
- Compact: 27-28 characters (e.g., `did:agentmesh:3J98t1WpEZ73CNmQvie`)
- No registry round-trip needed for basic verification
- Collision-resistant: 160-bit hash provides 2^80 collision resistance

### 4.2 Identity Convergence (ADR)

> **Decision:** Converge Python `did:mesh:` and TypeScript `did:agentmesh:`
> formats to the single `did:agentmesh:<fingerprint>` format defined above.
>
> **Rationale:** The fingerprint is derived from the public key, making it
> self-verifying. The `did:agentmesh:` prefix is more descriptive than
> `did:mesh:` and aligns with the package naming.
>
> **Migration:** Existing `did:mesh:` identifiers remain valid via a
> compatibility shim that accepts both prefixes. New identities MUST use
> `did:agentmesh:`.

### 4.3 Key Material

Each agent holds:

| Key | Type | Purpose | Lifetime |
|-----|------|---------|----------|
| Identity Key (IK) | Ed25519 | Signing, DID derivation | Long-lived |
| Identity Key (IK-X) | X25519 | DH operations (derived from IK) | Same as IK |
| Signed Pre-Key (SPK) | X25519 | X3DH, signed by IK | Rotated periodically (recommended: 7 days) |
| One-Time Pre-Keys (OPK) | X25519 | X3DH, consumed on use | Single-use |
| Ratchet Keys | X25519 | Double Ratchet DH steps | Per-message-turn |

### 4.4 Ed25519 to X25519 Conversion

Identity keys are Ed25519 (for signatures). X3DH requires X25519 (for DH).
The conversion uses the birational map defined in RFC 7748 Section 4.1:

```
x25519_private = ed25519_sk_to_curve25519(ed25519_private_key)
x25519_public  = ed25519_pk_to_curve25519(ed25519_public_key)
```

This is a standard operation available in libsodium (`crypto_sign_ed25519_pk_to_curve25519`),
`@noble/curves` (`edwardsToMontgomeryPub`), and equivalent libraries in
every target language.

---

## 5. Cryptographic Primitives

### 5.1 Cipher Suite

This protocol defines a single mandatory cipher suite:

```
AGENTMESH_X25519_CHACHA20POLY1305_SHA256
```

| Primitive | Algorithm | Parameters |
|-----------|-----------|------------|
| DH | X25519 | RFC 7748 |
| AEAD | ChaCha20-Poly1305 | RFC 8439, 96-bit nonce, 128-bit tag |
| Hash | SHA-256 | FIPS 180-4 |
| KDF | HKDF-SHA256 | RFC 5869 |
| Signature | Ed25519 | RFC 8032 |
| Key encoding | Raw 32-byte | Little-endian u-coordinate for X25519 |

### 5.2 HKDF Usage

All key derivation uses HKDF-SHA256 (RFC 5869) with domain-specific info strings:

| Usage | Salt | Info | Output length |
|-------|------|------|---------------|
| X3DH shared secret | `0xFF * 32` | `"AgentMesh_X3DH_v1"` | 32 bytes |
| Root key ratchet | Current root key | `"AgentMesh_Ratchet_v1"` | 64 bytes (32 root + 32 chain) |
| Chain key → message key | — | HMAC-SHA256 with `0x01` | 32 bytes |
| Chain key → next chain | — | HMAC-SHA256 with `0x02` | 32 bytes |

### 5.3 AEAD Construction

Messages are encrypted with ChaCha20-Poly1305 (RFC 8439):

```
nonce      = random(12)                    # 96-bit random nonce
aad        = header_bytes || associated_data
ciphertext = ChaCha20Poly1305.encrypt(key, nonce, plaintext, aad)
output     = nonce || ciphertext           # nonce prepended
```

**Associated Data (AAD)** binds the ciphertext to the message header and
agent identities, preventing header manipulation:

```
aad = serialize(header) || sender_did_bytes || recipient_did_bytes
```

---

## 6. Key Management

### 6.1 Pre-Key Bundle

An agent publishes a pre-key bundle to the registry for asynchronous
session establishment:

```json
{
  "version": 1,
  "agent_did": "did:agentmesh:3J98t1WpEZ73CNmQvie",
  "identity_key": "<base64url(x25519_public)>",
  "signed_pre_key": {
    "key_id": 42,
    "public_key": "<base64url(x25519_public)>",
    "signature": "<base64url(ed25519_signature)>"
  },
  "one_time_pre_keys": [
    { "key_id": 100, "public_key": "<base64url(x25519_public)>" },
    { "key_id": 101, "public_key": "<base64url(x25519_public)>" }
  ],
  "timestamp": "2026-04-21T19:00:00Z"
}
```

### 6.2 Signed Pre-Key Rotation

Signed pre-keys SHOULD be rotated every 7 days. The registry MUST retain
the previous signed pre-key for 14 days after rotation to allow in-flight
session establishments to complete.

### 6.3 One-Time Pre-Key Replenishment

One-time pre-keys are consumed on use. Agents SHOULD maintain at least
10 OPKs on the registry and replenish when the count drops below 5.

---

## 7. X3DH Key Agreement

Follows the Signal X3DH specification exactly, with these parameters:

```
curve = X25519
hash  = SHA-256
info  = "AgentMesh_X3DH_v1"
```

### 7.1 Initiator Flow

1. Fetch recipient's pre-key bundle from registry
2. Verify signed pre-key signature (Ed25519 over SPK public key)
3. Generate ephemeral X25519 key pair (EK)
4. Compute DH values:
   - `DH1 = DH(IK_sender, SPK_recipient)`
   - `DH2 = DH(EK_sender, IK_recipient)`
   - `DH3 = DH(EK_sender, SPK_recipient)`
   - `DH4 = DH(EK_sender, OPK_recipient)` (if OPK available)
5. Derive shared secret: `SK = HKDF(0xFF*32, DH1||DH2||DH3[||DH4], "AgentMesh_X3DH_v1", 32)`
6. Initialize Double Ratchet as sender with SK

### 7.2 Responder Flow

1. Receive initial message containing sender's IK, EK, and used OPK ID
2. Compute matching DH values (roles reversed)
3. Derive same shared secret SK
4. Initialize Double Ratchet as receiver with SK
5. Delete consumed OPK

### 7.3 Associated Data

```
AD = sender_identity_key_x25519 || recipient_identity_key_x25519
```

The AD is passed to the Double Ratchet and bound into every message's AEAD.

---

## 8. Double Ratchet

Follows the Signal Double Ratchet specification with these parameters:

### 8.1 Ratchet State

```
state = {
  dh_self:      X25519KeyPair,       # Current DH ratchet key pair
  dh_remote:    X25519PublicKey,      # Peer's current DH ratchet key
  root_key:     bytes[32],           # Root chain key
  chain_send:   bytes[32] | null,    # Sending chain key
  chain_recv:   bytes[32] | null,    # Receiving chain key
  n_send:       uint32,              # Send message counter
  n_recv:       uint32,              # Receive message counter
  pn:           uint32,              # Previous send chain length
  skipped:      Map<(bytes, uint32), bytes[32]>  # Skipped message keys
}
```

### 8.2 Symmetric Ratchet (KDF Chain)

```
message_key    = HMAC-SHA256(chain_key, 0x01)
next_chain_key = HMAC-SHA256(chain_key, 0x02)
```

### 8.3 DH Ratchet Step

Triggered when the received message's DH public key differs from `dh_remote`:

1. Cache skipped message keys for the current receiving chain
2. `dh_output = DH(dh_self.private, new_dh_remote)`
3. `root_key, chain_recv = KDF_ROOT(root_key, dh_output)`
4. Generate new DH key pair: `dh_self = X25519.generate()`
5. `dh_output = DH(dh_self.private, new_dh_remote)`
6. `root_key, chain_send = KDF_ROOT(root_key, dh_output)`
7. Reset send/receive counters

### 8.4 Skipped Message Keys

Maximum skipped keys per session: **100** (configurable).

Exceeding this limit MUST cause the session to reject the message with
an error. Skipped keys SHOULD be persisted for session resumption.

### 8.5 Session Serialization

Ratchet state MUST be serializable to JSON for persistence:

```json
{
  "dh_self_private": "<hex>",
  "dh_self_public": "<hex>",
  "dh_remote_public": "<hex>",
  "root_key": "<hex>",
  "chain_key_send": "<hex>",
  "chain_key_recv": "<hex>",
  "n_send": 0,
  "n_recv": 0,
  "pn": 0,
  "skipped_keys": { "<dh_pub_hex>:<n>": "<message_key_hex>" }
}
```

---

## 9. Message Envelope

### 9.1 Frame Format

All protocol frames are JSON objects with a `type` field and a `version` field:

```json
{
  "v": 1,
  "type": "<frame_type>",
  "from": "did:agentmesh:<fingerprint>",
  "to": "did:agentmesh:<fingerprint>",
  "id": "<uuid>",
  "ts": "<ISO-8601>",
  ...frame-specific fields
}
```

### 9.2 Frame Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `connect` | Client → Relay | Register presence, authenticate |
| `disconnect` | Client → Relay | Graceful disconnect |
| `knock` | Agent → Agent (via relay) | Intent-carrying session initiation |
| `knock_accept` | Agent → Agent (via relay) | Accept session with policy conditions |
| `knock_reject` | Agent → Agent (via relay) | Reject session with reason |
| `message` | Agent → Agent (via relay) | Encrypted application message |
| `ack` | Agent → Agent (via relay) | Delivery acknowledgment |
| `prekey_request` | Client → Registry | Fetch pre-key bundle |
| `prekey_response` | Registry → Client | Pre-key bundle |
| `prekey_upload` | Client → Registry | Publish pre-key bundle |
| `heartbeat` | Client → Relay | Keep-alive + presence |
| `error` | Any → Any | Error response |

### 9.3 Message Frame

The core encrypted message frame:

```json
{
  "v": 1,
  "type": "message",
  "from": "did:agentmesh:sender",
  "to": "did:agentmesh:recipient",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "ts": "2026-04-21T19:00:00Z",
  "header": {
    "dh": "<base64url(sender_dh_public_key)>",
    "pn": 5,
    "n": 0
  },
  "ciphertext": "<base64url(nonce || encrypted_payload)>"
}
```

**Header fields:**
- `dh` — sender's current DH ratchet public key (32 bytes, base64url)
- `pn` — previous sending chain length (for skipped key calculation)
- `n` — message number in the current sending chain

**Ciphertext:** 12-byte nonce prepended to ChaCha20-Poly1305 output.

### 9.4 Initial Message (X3DH)

The first message in a session includes X3DH establishment data:

```json
{
  "v": 1,
  "type": "message",
  "from": "did:agentmesh:sender",
  "to": "did:agentmesh:recipient",
  "id": "...",
  "ts": "...",
  "x3dh": {
    "identity_key": "<base64url(sender_x25519_identity_key)>",
    "ephemeral_key": "<base64url(sender_ephemeral_key)>",
    "used_opk_id": 100
  },
  "header": { "dh": "...", "pn": 0, "n": 0 },
  "ciphertext": "..."
}
```

The `x3dh` field is only present on the **first message** of a session.
The recipient uses it to perform the X3DH responder flow before decrypting.

---

## 10. KNOCK Intent Protocol

KNOCK is an intent-carrying handshake that precedes session establishment.
It allows the recipient to evaluate the initiator's stated intent before
accepting a session — integrating with AGT's governance layer.

### 10.1 KNOCK Frame

```json
{
  "v": 1,
  "type": "knock",
  "from": "did:agentmesh:sender",
  "to": "did:agentmesh:recipient",
  "id": "...",
  "ts": "...",
  "intent": {
    "action": "delegate_task",
    "description": "Process customer refund #12345",
    "capabilities_required": ["payments:write", "crm:read"],
    "trust_minimum": 700
  },
  "signature": "<base64url(ed25519_signature_over_canonical_intent)>"
}
```

### 10.2 KNOCK Accept

```json
{
  "v": 1,
  "type": "knock_accept",
  "from": "did:agentmesh:recipient",
  "to": "did:agentmesh:sender",
  "id": "...",
  "ts": "...",
  "knock_id": "<id of the original knock>",
  "conditions": {
    "max_messages": 100,
    "ttl_seconds": 3600,
    "allowed_actions": ["payments:write"]
  },
  "signature": "<base64url(ed25519_signature)>"
}
```

### 10.3 KNOCK Reject

```json
{
  "v": 1,
  "type": "knock_reject",
  "from": "did:agentmesh:recipient",
  "to": "did:agentmesh:sender",
  "id": "...",
  "knock_id": "<id of the original knock>",
  "reason": "insufficient_trust",
  "signature": "<base64url(ed25519_signature)>"
}
```

### 10.4 Governance Integration

Before accepting a KNOCK, the recipient's governance layer evaluates:
1. Is the sender's DID registered and active?
2. Does the sender's trust score meet the `trust_minimum`?
3. Does the sender hold the `capabilities_required`?
4. Does the stated `intent.action` pass the policy engine?

Only if all checks pass does the recipient send `knock_accept` and proceed
to X3DH key exchange.

---

## 11. Registry API

The registry is a REST service that stores agent metadata, pre-key bundles,
and provides discovery.

### 11.1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/agents` | Register agent |
| `GET` | `/v1/agents/{did}` | Get agent metadata |
| `DELETE` | `/v1/agents/{did}` | Deregister agent |
| `PUT` | `/v1/agents/{did}/prekeys` | Upload pre-key bundle |
| `GET` | `/v1/agents/{did}/prekeys` | Fetch pre-key bundle (consumes one OPK) |
| `GET` | `/v1/agents/{did}/presence` | Get presence/last-seen |
| `POST` | `/v1/agents/{did}/reputation` | Submit reputation feedback |
| `GET` | `/v1/discover` | Search agents by capability |

### 11.2 Agent Registration

```
POST /v1/agents
Authorization: Ed25519-Timestamp <did> <timestamp> <signature>

{
  "did": "did:agentmesh:3J98t1WpEZ73CNmQvie",
  "public_key": "<base64url(ed25519_public)>",
  "capabilities": ["data:read", "data:write"],
  "metadata": {
    "name": "trading-agent",
    "framework": "langchain",
    "version": "1.0.0"
  }
}
```

### 11.3 Pre-Key Fetch

```
GET /v1/agents/did:agentmesh:3J98t1WpEZ73CNmQvie/prekeys
Authorization: Ed25519-Timestamp <did> <timestamp> <signature>
```

Response includes one OPK (consumed atomically):

```json
{
  "identity_key": "<base64url>",
  "signed_pre_key": { "key_id": 42, "public_key": "<base64url>", "signature": "<base64url>" },
  "one_time_pre_key": { "key_id": 100, "public_key": "<base64url>" }
}
```

If no OPKs remain, `one_time_pre_key` is `null` and the initiator
performs 3-DH (without DH4).

---

## 12. Relay Service

The relay provides store-and-forward delivery for agents that may be
offline.

### 12.1 Architecture

```
Agent A ──WebSocket──► Relay ──WebSocket──► Agent B
                         │
                    ┌────▼─────┐
                    │ Inbox DB │  (offline messages)
                    └──────────┘
```

### 12.2 Connection

```json
{
  "v": 1,
  "type": "connect",
  "from": "did:agentmesh:sender",
  "auth": {
    "timestamp": "2026-04-21T19:00:00Z",
    "signature": "<base64url(ed25519_sign(timestamp))>"
  }
}
```

### 12.3 Store-and-Forward

- Messages for offline agents are stored in the relay's inbox database
- **TTL:** 72 hours (configurable per deployment)
- **Delivery:** on reconnect, the relay pushes all pending messages
- **Ordering:** messages are delivered in send-order per sender
- **Deduplication:** message `id` (UUID) is used for idempotent delivery
- **Acknowledgment:** recipient sends `ack` frame; relay deletes from inbox

### 12.4 Heartbeat

```json
{
  "v": 1,
  "type": "heartbeat",
  "from": "did:agentmesh:sender",
  "ts": "2026-04-21T19:00:00Z"
}
```

Interval: **30 seconds**. Relay marks agent as offline after **3 missed
heartbeats** (90 seconds).

### 12.5 Ciphertext-Only Storage

The relay stores **only ciphertext**. It cannot decrypt messages. The relay
sees: sender DID, recipient DID, message ID, timestamp, and opaque
ciphertext. This is by design — the relay is untrusted for content.

---

## 13. Authentication

### 13.1 Ed25519-Timestamp (Default)

The default authentication scheme for all registry and relay requests:

```
Authorization: Ed25519-Timestamp <did> <iso8601_timestamp> <base64url(signature)>
```

Where `signature = Ed25519.sign(private_key, utf8(iso8601_timestamp))`.

The server verifies:
1. Timestamp is within the **replay window** (±5 minutes)
2. DID is registered
3. Signature is valid against the registered public key

### 13.2 SPIFFE/SVID (Enterprise)

For enterprise deployments with PKI infrastructure:

```
Authorization: Bearer <SVID-JWT>
```

Where the SVID JWT contains the agent's SPIFFE ID mapped to the DID.

### 13.3 Auth Mode Selection

Deployments declare their auth mode in the relay/registry configuration:

```yaml
auth_mode: "ed25519"   # Default — works everywhere
# auth_mode: "svid"    # Enterprise — requires SPIFFE infrastructure
# auth_mode: "hybrid"  # Accept both
```

---

## 14. Governance Integration

### 14.1 Pre-Send Policy Check

Before encrypting and sending a message, the governance layer evaluates:

```python
result = policy_engine.evaluate({
    "action": "agentmesh.send",
    "sender": sender_did,
    "recipient": recipient_did,
    "intent": knock_intent,       # from the KNOCK that opened this session
    "message_number": n_send,
    "session_age_seconds": elapsed,
})
if not result.allowed:
    raise PermissionError(result.reason)
```

### 14.2 Post-Receive Policy Check

Before returning decrypted content to the application:

```python
result = policy_engine.evaluate({
    "action": "agentmesh.receive",
    "sender": sender_did,
    "recipient": self_did,
    "content_hash": sha256(plaintext),
})
```

### 14.3 Audit

Every message send/receive attempt is logged to the AGT audit trail:

```json
{
  "event": "agentmesh.message",
  "direction": "send",
  "sender": "did:agentmesh:...",
  "recipient": "did:agentmesh:...",
  "message_id": "...",
  "session_id": "...",
  "policy_decision": "allow",
  "timestamp": "..."
}
```

---

## 15. Protocol Versioning

### 15.1 Version Field

Every frame contains `"v": <integer>`. This specification defines `v: 1`.

### 15.2 Version Negotiation

During the `connect` frame, clients declare supported versions:

```json
{
  "v": 1,
  "type": "connect",
  "supported_versions": [1],
  ...
}
```

The relay responds with the highest mutually supported version.

### 15.3 Future Versions

| Version | Description |
|---------|-------------|
| 1 | This specification (Signal Protocol, pair-wise) |
| 2 (planned) | MLS group messaging (RFC 9420) |
| 3 (planned) | Post-quantum key encapsulation (ML-KEM) |

---

## 16. Security Considerations

### 16.1 Trust Model

- The **relay** is untrusted for content (sees only ciphertext) but trusted
  for delivery (can drop or delay messages)
- The **registry** is trusted for pre-key distribution (a compromised
  registry can perform MitM by substituting pre-keys)
- **Agents** authenticate via Ed25519 signatures bound to their DID

### 16.2 Forward Secrecy

The Double Ratchet provides forward secrecy: each message key is derived
from the ratchet state and immediately discarded after use. Compromising
the current ratchet state reveals only future messages (which are protected
by post-compromise security via DH ratchet steps).

### 16.3 Replay Protection

- Each message key is single-use (derived from the chain ratchet)
- The relay deduplicates by message `id` (UUID)
- Skipped message keys have a configurable maximum (default: 100)

### 16.4 Denial of Service

- Relay enforces per-agent rate limits (configurable)
- Registry enforces pre-key upload rate limits
- KNOCK protocol allows recipients to reject sessions before key exchange

### 16.5 Known Limitations

- **No group messaging** in v1 — pair-wise only
- **No post-quantum key exchange** in v1 — X25519 only
- **Relay can observe traffic patterns** (who talks to whom, when, message sizes)
- **No workflow-level correlation** — governance evaluates individual messages,
  not sequences

---

## 17. Test Vectors

### 17.1 X3DH Test Vector

```
Alice IK (Ed25519 private):
  a]b]c]d] (64 bytes hex — to be filled with actual test vector)

Alice IK (Ed25519 public):
  (32 bytes hex)

Alice IK (X25519 private, converted):
  (32 bytes hex)

Alice IK (X25519 public, converted):
  (32 bytes hex)

Bob SPK:
  (key pair + signature)

Expected shared secret:
  (32 bytes hex)
```

> **Note:** Full test vectors with actual cryptographic values will be
> generated from the reference Python implementation and cross-validated
> against the TypeScript implementation before this spec is finalized.

### 17.2 Double Ratchet Test Vector

A complete 5-message conversation with expected intermediate ratchet
states will be provided as a JSON file at `tests/vectors/ratchet-v1.json`.

### 17.3 Envelope Serialization Test Vector

Canonical JSON serialization of each frame type will be provided at
`tests/vectors/envelope-v1.json`.

---

## 18. References

1. [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/) — CC0
2. [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/) — CC0
3. [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748) (X25519)
4. [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
5. [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
6. [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
7. [RFC 9420 — MLS](https://www.rfc-editor.org/rfc/rfc9420)
8. [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
9. [SPIFFE/SVID Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
