# 2026-07-21 — AgentMesh message authentication and plaintext-downgrade hardening

PR: [microsoft/agent-governance-toolkit#3411](https://github.com/microsoft/agent-governance-toolkit/pull/3411)

## What changed and why

This PR closes a set of related message-authentication gaps in AgentMesh: two
on the TypeScript `MeshClient` receive path
(`agent-governance-typescript/src/encryption/mesh-client.ts`) and two on the
Python relay (`agent-governance-python/agent-mesh/src/agentmesh/relay/`). In
each case a peer could influence a security decision — how a frame is
authenticated, or whose message may be deleted — that should be made solely
from the receiver's own verified state.

### 1. MeshClient: the plaintext path is selected only by receiver configuration

```ts
// before — a sender-controlled wire flag can select the no-crypto path
if (frame.plaintext || this.isPlaintextPeer(from)) {
  // Legacy plaintext
```

The `plaintext` boolean travels in the wire frame and is therefore controlled
by the sender. Honoring it let a sender skip the X3DH / Double Ratchet / AEAD
path entirely and have the receiver accept the body at face value, including an
arbitrary `from` DID. The fix decides the legacy path solely from the
receiver's own operator allowlist (`isPlaintextPeer(from)`) and never from the
wire flag. A peer that is not explicitly allow-listed always takes the
encrypted branch and is dropped if it cannot be cryptographically
authenticated.

### 2. MeshClient: an established encrypted session is never silently downgraded

Even for a peer that *is* on the plaintext allowlist, if an encrypted session
already exists for it (`this.sessions.get(from)?.channel`), an inbound
plaintext frame is a downgrade of that live channel and is dropped rather than
processed. A negotiated encrypted session can no longer be pushed back to the
no-crypto path by a later plaintext frame.

### 3. MeshClient: encrypted frames must carry a ratchet header

An encrypted `message` frame whose ratchet `header.dh` is missing or is not a
string is now dropped cleanly through the client's error handler, instead of
throwing out of the receive path. This removes a headerless-frame code path
that a peer could use to disrupt the receive loop.

### 4. Relay: the frame `from` is bound to the connection's verified identity

The relay authenticates *which mailbox a socket owns* at connect time via DID
proof-of-possession (`_verify_connect_pop`). `_handle_message` now additionally
binds the `from` a peer writes into a message or knock body to that verified
identity:

```python
if _REQUIRE_DID_POP:
    if claimed_from is not None and claimed_from != sender_did:
        # drop frames attributed to a DID this connection does not own
        return
    # stamp the verified identity so every stored/forwarded frame carries an
    # authenticated `from`, even one that omitted it
    frame["from"] = sender_did
```

A connected peer can therefore no longer emit message or knock frames
attributed to a DID it does not own. The binding is enforced only when DID
proof-of-possession is required (the secure default); when it is disabled,
`sender_did` itself is unverified, so the check adds no security and is
skipped.

### 5. Relay: only the recipient may acknowledge a stored message

The relay previously deleted an offline-stored message on receipt of any `ack`
frame carrying that message id, without checking that the acknowledging agent
was the message's intended recipient. Per the wire spec (section 12.3) only the
recipient acknowledges delivery, after which the relay deletes the message.

`InboxStore.acknowledge` now accepts an optional `recipient_did` and deletes
only when it matches the stored message's recipient; the relay passes the
connection's verified `sender_did`. An `ack` referencing another agent's
message id — an ack spray across guessed ids — no longer removes messages
queued for a different agent.

## Threat model impact

These changes strengthen sender authentication and message-deletion access
control on the AgentMesh transport. They remove sender influence over security
decisions; they do not add new inputs, network exposure, or trust decisions.

| Dimension | Direction |
|---|---|
| Sender authentication (spoofed `from`) | **Strengthened.** A frame's `from` is bound to the connect-time, DID proof-of-possession-verified identity, so a peer cannot be attributed a DID it does not own. An omitted `from` is stamped with the verified identity rather than forwarded absent. |
| Plaintext downgrade (wire flag) | **Closed.** The no-crypto path is selected only from the receiver's own allowlist; the sender-controlled `plaintext` flag can no longer bypass X3DH / Double Ratchet / AEAD. |
| Session downgrade | **Strengthened.** A peer with an established encrypted session is never silently moved to the plaintext path, even if it is also allow-listed for plaintext. |
| Headerless encrypted frame | **Strengthened.** An encrypted frame with no ratchet header fails closed through the error handler instead of throwing out of the receive loop. |
| Message-deletion access control (acks) | **Strengthened.** Only the message's own recipient — identified by the connection's verified DID — can acknowledge and delete it, so one agent can no longer delete another agent's queued messages. |
| New attack surface | **None.** No new inputs, endpoints, or trust decisions; each change narrows an existing decision to verified state. |
| Backward compatibility | **Narrow.** Senders that relied on the `plaintext` wire flag to a peer *not* on the receiver's allowlist are now dropped; this was the vulnerable behavior. Operator-allowlisted plaintext peers with no encrypted session are unchanged. Compliant senders already set `from` to their own DID, so the `from` binding is a no-op for them. |

### Specific considerations

- **No downgrade negotiation.** In every case the receiver decides from its own
  verified state (its `plaintextPeers` allowlist, its session table, its
  connect-time DID proof-of-possession), so there is no field an attacker can
  set to force a weaker path; a mismatched peer fails closed.
- **Consistent enforcement point.** Knock frames (`knock`, `knock_accept`,
  `knock_reject`) route through `_handle_message`, so the `from` binding covers
  them as well as `message` frames.

## Test coverage

TypeScript — `agent-governance-typescript/tests/mesh-client-plaintext-downgrade.test.ts`:

| Test | Purpose |
|---|---|
| `plaintext:true from a non-allow-listed sender is dropped, not delivered` | The sender-controlled wire flag cannot select the plaintext path. |
| `plaintext:true against an established encrypted session is dropped; ratchet untouched` | A plaintext frame cannot downgrade a live encrypted session, and the ratchet state is not mutated. |
| `allow-listed plaintext peer with a live encrypted session: plaintext frame is dropped` | Allowlist membership does not permit downgrading an existing session. |
| `no regression: allow-listed plaintext peer without a session is still delivered` | Legitimate operator-allowlisted plaintext delivery still works. |
| `plaintext handling is never selected by the wire flag alone` | Path selection depends only on receiver configuration. |

Python relay / store — `agent-governance-python/agent-mesh/tests/test_relay.py`:

| Test | Purpose |
|---|---|
| `test_acknowledge_rejects_non_recipient` | Store level: `InMemoryInboxStore.acknowledge` refuses to delete when the supplied recipient DID does not match the stored message. |
| `test_ack_from_non_recipient_is_ignored` | End to end: an ack from a non-recipient does not delete another agent's queued message. |
| `test_spoofed_from_is_dropped` | A `message` frame whose `from` does not match the verified connection identity is dropped. |
| `test_spoofed_knock_from_is_dropped` | The same binding applies to knock frames. |
| `test_missing_from_is_stamped_with_authenticated_identity` | An omitted `from` is stamped with the sender's verified DID on delivery. |
