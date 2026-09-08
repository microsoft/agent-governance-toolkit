---
title: "2026-07-21 — AgentMesh message authentication and plaintext-downgrade hardening"
last_reviewed: 2026-07-30
owner: agt-maintainers
---

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

Even for a peer that *is* on the plaintext allowlist, once that peer has been
end-to-end verified the plaintext path is permanently closed for it.

A live-channel check alone (`this.sessions.get(from)?.channel`) is **not**
sufficient, and relying on it was the original form of this hardening. Several
paths delete the session, and each one re-opens the plaintext gate for a peer
that had already been cryptographically verified:

* the Gap-G3 ratchet-desync handler calls `closeSession()` after a single
  decrypt failure — a malicious relay forces that with one garbage-ciphertext
  frame and downgrades with the next (a two-frame attack);
* `handleKnockReject()` calls `closeSession()` on an **unauthenticated**
  `knock_reject` frame — the same downgrade in a single frame, with no crypto
  interaction at all.

The gate therefore also latches on `e2eVerifiedSet`, which is only ever added
to and never cleared. Once a peer has produced a successfully decrypted frame,
it can never again be handled as plaintext for the lifetime of the client,
regardless of how (or how often) its session is torn down. This makes the
guarantee teardown-path-agnostic rather than dependent on enumerating every
current call site of `closeSession()`.

A peer that is allow-listed for plaintext and has *never* been E2E-verified is
unaffected and continues to receive plaintext normally.

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

### 6. Relay: a displaced connection is closed with an attributable code

When a second connection authenticates for a DID, the relay closes the previous
socket so messages are not routed to a ghost connection. That close used code
`1000` (Normal Closure), which `MeshClient` maps to `reason: "client"` — exactly
what it reports when the agent calls `disconnect()` on itself.

The consequence is a detection gap rather than an access-control gap: an agent
that was displaced *involuntarily* could not distinguish being taken over from
having closed its own socket, and it did not reconnect. Any successful
impersonation of the connect handshake therefore produced a silent eviction of
the legitimate owner that could not be detected or reported.

The relay now closes displaced sockets with `WS_CLOSE_SESSION_REPLACED` (`4006`)
and logs at warning level. `MeshClient` reports it as a server-initiated close
and raises it through `onError`, so a host can alert on it, while still
suppressing auto-reconnect for this specific code — reconnecting would displace
the socket that just replaced it and the two would evict each other in a loop.

This does not by itself prevent a takeover; it makes one observable. The
underlying connect-frame proof-of-possession replay window is tracked separately
(see *Known gaps*, [#3525](https://github.com/microsoft/agent-governance-toolkit/issues/3525)).

## Threat model impact

These changes strengthen sender authentication and message-deletion access
control on the AgentMesh transport. They remove sender influence over security
decisions; they do not add new inputs, network exposure, or trust decisions.

| Dimension | Direction |
|---|---|
| Sender authentication (spoofed `from`) | **Strengthened.** A frame's `from` is bound to the connect-time, DID proof-of-possession-verified identity, so a peer cannot be attributed a DID it does not own. An omitted `from` is stamped with the verified identity rather than forwarded absent. |
| Plaintext downgrade (wire flag) | **Closed.** The no-crypto path is selected only from the receiver's own allowlist; the sender-controlled `plaintext` flag can no longer bypass X3DH / Double Ratchet / AEAD. |
| Session downgrade | **Strengthened.** Once a peer has been end-to-end verified it is never moved to the plaintext path again, even if it is also allow-listed for plaintext and even if its session is subsequently torn down (ratchet desync, `knock_reject`, or an explicit `closeSession()`). The guarantee latches on `e2eVerifiedSet` rather than on the presence of a live channel, so it does not depend on enumerating every session-teardown path. |
| Headerless encrypted frame | **Strengthened.** An encrypted frame with no ratchet header fails closed through the error handler instead of throwing out of the receive loop. |
| Message-deletion access control (acks) | **Strengthened.** Only the message's own recipient — identified by the connection's verified DID — can acknowledge and delete it, so one agent can no longer delete another agent's queued messages. |
| Takeover detectability | **Strengthened.** A displaced connection is closed with a distinct code (`WS_CLOSE_SESSION_REPLACED`) instead of `1000`, so an involuntary eviction is reported to the host as a server close and raised through `onError` rather than being indistinguishable from a self-initiated disconnect. Detection only — see *Known gaps* for the underlying replay window. |
| New attack surface | **None.** No new inputs, endpoints, or trust decisions; each change narrows an existing decision to verified state. |
| Backward compatibility | **Narrow.** Senders that relied on the `plaintext` wire flag to a peer *not* on the receiver's allowlist are now dropped; this was the vulnerable behavior. Operator-allowlisted plaintext peers with no encrypted session are unchanged. Compliant senders already set `from` to their own DID, so the `from` binding is a no-op for them. |

### Specific considerations

- **No downgrade negotiation.** In every case the receiver decides from its own
  verified state (its `plaintextPeers` allowlist, its session table, its
  `e2eVerifiedSet` latch, its connect-time DID proof-of-possession), so there is
  no field an attacker can
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
| `two-frame desync must not re-open the plaintext gate for an E2E-verified peer` | A forced ratchet desync tears the session down, but the `e2eVerifiedSet` latch keeps the plaintext path closed on the following frame. |
| `injected knock_reject must not re-open the plaintext gate for an E2E-verified peer` | An unauthenticated `knock_reject` deletes the session but still cannot re-open the plaintext path. |
| `a peer latched by a real decrypt is refused plaintext after session teardown` | The latch is set by the production decrypt path (not test seeding) and outlives an explicit `closeSession()`. |
| `no regression: never-verified allow-listed peer still receives plaintext after a teardown` | The latch keys on E2E verification, not on "has ever had a session" — legitimate plaintext peers are unaffected. |

`agent-governance-typescript/tests/mesh-client-malformed-frame.test.ts`:

| Test | Purpose |
|---|---|
| `one malformed pending message does not discard the rest of the batch` | A single poisoned entry in a relay-supplied `pending_messages` batch is surfaced and skipped rather than aborting the drain and silently suppressing the remaining mail. |
| `a null pending entry does not abort the drain or suppress messages behind it` | Non-object entries (`null`, strings, numbers) in a relay-supplied batch are rejected, reported to `onError`, and skipped. Guards the isolation above against a `null` entry, where naively reading `msg.from` inside the catch throws a second time and the report is lost. |

Python relay / store — `agent-governance-python/agent-mesh/tests/test_relay.py`:

| Test | Purpose |
|---|---|
| `test_acknowledge_rejects_non_recipient` | Store level: `InMemoryInboxStore.acknowledge` refuses to delete when the supplied recipient DID does not match the stored message. |
| `test_ack_from_non_recipient_is_ignored` | End to end: an ack from a non-recipient does not delete another agent's queued message. |
| `test_spoofed_from_is_dropped` | A `message` frame whose `from` does not match the verified connection identity is dropped. |
| `test_spoofed_knock_from_is_dropped` | The same binding applies to knock frames. |
| `test_missing_from_is_stamped_with_authenticated_identity` | An omitted `from` is stamped with the sender's verified DID on delivery. |
| `test_knock_accept_and_reject_from_binding_is_enforced` | `knock_accept` / `knock_reject` inherit the same `from` binding, so a KNOCK verdict cannot be forged for a DID the sender does not own. |
| `test_spoofed_from_to_offline_recipient_is_not_stored` | The `from` binding also covers the offline path — a spoofed frame is not persisted into an offline recipient's inbox for later delivery. |
| `test_ack_replayed_across_connections_is_scoped_to_recipient` | Ack ownership is resolved from the identity of the connection the frame arrived on, proven with the recipient and the attacker connected *concurrently* and the same message id acknowledged from both sockets. |
| `test_replaced_session_uses_distinct_close_code` | A displaced socket is closed with `WS_CLOSE_SESSION_REPLACED`, not `1000`, so an involuntary takeover is distinguishable from a self-initiated disconnect. |

`agent-governance-typescript/tests/mesh-client-auto-reconnect.test.ts`:

| Test | Purpose |
|---|---|
| `session-replaced close (4006) is server-attributed, surfaced, and does NOT reconnect` | The client reports the displacement as a server close, raises it through `onError` so a host can alert on a takeover, and suppresses auto-reconnect so the displaced and replacing sockets do not evict each other in a loop. |

## Known gaps

Deliberately out of scope for this change, recorded so they are not lost. Both
pre-date it and neither is introduced or worsened by it.

### Connect-frame proof-of-possession is replayable within its window

`_verify_connect_pop` (`agentmesh/relay/app.py`) signs only an ISO timestamp and
accepts it inside a ±5 minute window. The signature is not bound to a
server-issued nonce, to the relay URL, or to the TLS channel, so a captured
connect frame can be replayed inside that window to authenticate as the
captured DID. The consequences are real and are amplified by the ack-ownership
control added here: a replayed connect frame owns the mailbox, so it passes the
recipient check and can acknowledge — and therefore delete — the victim's queued
messages, and it displaces the victim's live socket.

The fix is a challenge-response nonce, or signing `relay_url || nonce` rather
than a bare timestamp. That changes the connect handshake on both sides and is
tracked in [#3525](https://github.com/microsoft/agent-governance-toolkit/issues/3525).

Mitigation in the meantime: the displacement is now observable
(`WS_CLOSE_SESSION_REPLACED`, section 6), and the transport requires TLS in
production, which prevents passive capture of connect frames on the wire.

### Offline-store deduplication is keyed globally by message id

`InMemoryInboxStore.store` (`agentmesh/relay/store.py`) treats `message_id` as
globally unique rather than unique per recipient, so a message whose id already
exists is dropped regardless of who it is addressed to. An attacker who could
*predict* a future message id could pre-store it and suppress the real message.

Not currently exploitable: ids are generated with `crypto.randomUUID()`
(`mesh-client.ts`), a 122-bit random key space, so they cannot be predicted or
enumerated. A correct fix re-keys `_messages` by `(recipient_did, message_id)`,
which also changes `acknowledge` and `fetch_pending`, and is tracked in
[#3526](https://github.com/microsoft/agent-governance-toolkit/issues/3526).
