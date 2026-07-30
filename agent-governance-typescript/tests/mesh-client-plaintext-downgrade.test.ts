// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Security regression tests: plaintext-downgrade / sender-spoof hardening.
 *
 * A sender-controlled wire boolean (`frame.plaintext`) must NOT be able to
 * select the legacy no-crypto receive path. Whether an inbound message is
 * treated as plaintext is decided SOLELY by the receiver's own operator
 * configuration (`plaintextPeers`, via `isPlaintextPeer(from)`). These tests
 * assert that forged / downgrade frames are dropped, while a legitimately
 * configured plaintext peer still works (no regression).
 */

import { MeshClient, type MeshClientOptions } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
import { ed25519 } from "@noble/curves/ed25519";

class MockWebSocket {
  sent: Array<Record<string, unknown>> = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(_url: string) {
    queueMicrotask(() => {
      if (this.onopen) this.onopen();
    });
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(): void {
    if (this.onclose) this.onclose();
  }

  simulateFrame(frame: Record<string, unknown>): void {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(frame) });
  }
}

let lastMockWs: MockWebSocket | null = null;

function mockWsFactory(url: string): WebSocket {
  const ws = new MockWebSocket(url);
  lastMockWs = ws;
  return ws as unknown as WebSocket;
}

function makeKeyManager(): X3DHKeyManager {
  const priv = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(priv);
  return new X3DHKeyManager(priv, pub);
}

const SELF_DID = "did:agentmesh:test-agent";

function makeClient(overrides?: Partial<MeshClientOptions>): MeshClient {
  return new MeshClient({
    relayUrl: "http://localhost:8080",
    registryUrl: "http://localhost:8081",
    keyManager: makeKeyManager(),
    agentDid: SELF_DID,
    wsFactory: mockWsFactory,
    autoRegister: false,
    ...overrides,
  });
}

/** Minimal fake ratchet channel whose receive() must never be invoked. */
interface FakeChannel {
  receive: (message: unknown) => Uint8Array;
  /**
   * A real DoubleRatchet channel exposes close(); closeSession() calls it
   * before deleting the session. Omitting it makes closeSession() throw and
   * silently skip the delete, which would mask session-teardown regressions.
   */
  close: () => void;
}

interface MeshClientInternals {
  sessions: Map<
    string,
    {
      peerId: string;
      channel: FakeChannel | null;
      isPlaintext: boolean;
      createdAt: Date;
      messageCount: number;
    }
  >;
  knockAccepted: Set<string>;
  preKnockBuffer: Map<string, unknown[]>;
  e2eVerifiedSet: Set<string>;
}

function internals(client: MeshClient): MeshClientInternals {
  return client as unknown as MeshClientInternals;
}

/**
 * Inject a fully-established encrypted session for `peerDid` — a live channel
 * plus knockAccepted — simulating a peer with a negotiated X3DH + Double
 * Ratchet session. By default the channel's receive() throws if the ratchet is
 * ever consulted, so a silent plaintext downgrade is provable by its
 * non-invocation. Pass `receiveImpl` to simulate a working ratchet (returns the
 * decrypted bytes) when the test needs to assert that a genuine encrypted frame
 * is decrypted rather than dropped.
 */
function injectEncryptedSession(
  client: MeshClient,
  peerDid: string,
  receiveImpl?: (message: unknown) => Uint8Array,
): { receiveInvoked: () => boolean } {
  let invoked = false;
  const channel: FakeChannel = {
    receive: (message: unknown) => {
      invoked = true;
      if (receiveImpl) return receiveImpl(message);
      throw new Error("ratchet channel.receive() must not be invoked for a forged plaintext frame");
    },
    close: () => { /* no-op: real channels release ratchet state here */ },
  };
  internals(client).sessions.set(peerDid, {
    peerId: peerDid,
    channel,
    isPlaintext: false,
    createdAt: new Date(),
    messageCount: 0,
  });
  internals(client).knockAccepted.add(peerDid);
  return { receiveInvoked: () => invoked };
}

function plaintextFrame(from: string, payload: unknown): Record<string, unknown> {
  return {
    v: 1,
    type: "message",
    from,
    to: SELF_DID,
    id: "forged-1",
    ts: new Date().toISOString(),
    ciphertext: btoa(JSON.stringify(payload)),
    plaintext: true,
  };
}

/** A well-formed encrypted `message` frame carrying a ratchet header. */
function encryptedFrame(from: string, payload: unknown): Record<string, unknown> {
  return {
    v: 1,
    type: "message",
    from,
    to: SELF_DID,
    id: "enc-1",
    ts: new Date().toISOString(),
    header: { dh: btoa("dh-public-key"), pn: 0, n: 0 },
    ciphertext: btoa(JSON.stringify(payload)),
  };
}

const tick = () => new Promise((r) => setTimeout(r, 50));

describe("MeshClient plaintext-downgrade / sender-spoof hardening", () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    lastMockWs = null;
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  // Sender spoof: a brand-new `from` (not operator-allow-listed for plaintext)
  // sets plaintext:true. Must NOT be delivered.
  test("plaintext:true from a non-allow-listed sender is dropped, not delivered", async () => {
    const client = makeClient({ preKnockBufferSize: 0 });
    const received: Array<{ from: string; payload: unknown }> = [];
    const errors: Array<{ kind: string; from: string }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));
    client.onError((kind, from) => errors.push({ kind, from }));

    await client.connect();

    const attacker = "did:mesh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    lastMockWs!.simulateFrame(
      plaintextFrame(attacker, { cmd: "transfer", amount: 1000000, to: "attacker" }),
    );
    await tick();

    expect(received).toHaveLength(0);
    // Not allow-listed => encrypted path => no session => dropped.
    expect(errors).toContainEqual({ kind: "decrypt", from: attacker });
  });

  // Downgrade of a fully established encrypted session. The peer has a live
  // channel + knockAccepted; a plaintext:true frame must be dropped and the
  // ratchet must never be consulted.
  test("plaintext:true against an established encrypted session is dropped; ratchet untouched", async () => {
    const client = makeClient();
    const received: unknown[] = [];
    const errors: Array<{ kind: string }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));
    client.onError((kind) => errors.push({ kind }));

    await client.connect();

    const peer = "did:mesh:realpeerrealpeerrealpeerreal0001";
    const session = injectEncryptedSession(client, peer);

    lastMockWs!.simulateFrame(
      plaintextFrame(peer, { cmd: "transfer", amount: 999999, to: "attacker" }),
    );
    await tick();

    expect(received).toHaveLength(0);
    expect(session.receiveInvoked()).toBe(false);
    // Session must NOT be silently torn down or downgraded.
    expect(internals(client).sessions.get(peer)?.channel).not.toBeNull();
    // Encrypted branch drops the headerless forged frame.
    expect(errors).toContainEqual({ kind: "decrypt" });
  });

  // Defense-in-depth: even a peer that IS operator-allow-listed for plaintext
  // must not be downgraded once an encrypted session exists. The plaintext /
  // headerless frame now falls through to the encrypted path and fails closed
  // on the missing-ratchet-header check, so it is dropped and the ratchet is
  // never consulted.
  test("allow-listed plaintext peer with a live encrypted session: plaintext frame is dropped", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: unknown[] = [];
    const errors: Array<{ kind: string }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));
    client.onError((kind) => errors.push({ kind }));

    await client.connect();

    const session = injectEncryptedSession(client, peer);

    lastMockWs!.simulateFrame(plaintextFrame(peer, { text: "downgrade-me" }));
    await tick();

    expect(received).toHaveLength(0);
    expect(session.receiveInvoked()).toBe(false);
    // Dropped on the encrypted path's ratchet-header check (fail-closed).
    expect(errors).toContainEqual({ kind: "decrypt" });
  });

  // Copilot review follow-up (mesh-client.ts:816): a peer that is allow-listed
  // for plaintext AND has a live encrypted session must still be able to receive
  // genuine encrypted frames — the plaintext branch must not black-hole them.
  // The frame carries a ratchet header, so it flows through to the ratchet and
  // is delivered as an encrypted (isPlaintext=false) message.
  test("allow-listed plaintext peer with a live encrypted session: valid encrypted frame is decrypted, not dropped", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ from: string; payload: unknown; isPlaintext: boolean }> = [];
    const errors: Array<{ kind: string }> = [];
    client.onMessage((from, payload, isPlaintext) => received.push({ from, payload, isPlaintext }));
    client.onError((kind) => errors.push({ kind }));

    await client.connect();

    // A working ratchet that returns the decrypted payload bytes.
    const session = injectEncryptedSession(client, peer, () =>
      new TextEncoder().encode(JSON.stringify({ text: "hello-encrypted" })),
    );

    lastMockWs!.simulateFrame(encryptedFrame(peer, { ciphertext: "opaque" }));
    await tick();

    expect(session.receiveInvoked()).toBe(true);
    expect(received).toEqual([
      { from: peer, payload: { text: "hello-encrypted" }, isPlaintext: false },
    ]);
    expect(errors).toHaveLength(0);
  });

  // No regression: a legitimately configured plaintext peer (no encrypted
  // session) is still delivered on the plaintext path.
  test("no regression: allow-listed plaintext peer without a session is still delivered", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ from: string; payload: unknown }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));

    await client.connect();

    lastMockWs!.simulateFrame(plaintextFrame(peer, { text: "legit-plaintext" }));
    await tick();

    expect(received).toEqual([{ from: peer, payload: { text: "legit-plaintext" } }]);
  });

  // The spoof is rejected regardless of the sender-supplied boolean: a peer not
  // allow-listed cannot get plaintext handling even by omitting `plaintext`.
  test("plaintext handling is never selected by the wire flag alone", async () => {
    const client = makeClient({ preKnockBufferSize: 0 });
    const received: unknown[] = [];
    client.onMessage((from, payload) => received.push({ from, payload }));

    await client.connect();

    // Same forged frame but WITHOUT the plaintext flag — behaviour is identical
    // (dropped), proving the flag is not what gates delivery.
    const frame = plaintextFrame("did:mesh:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", { x: 1 });
    delete frame.plaintext;
    lastMockWs!.simulateFrame(frame);
    await tick();

    expect(received).toHaveLength(0);
  });

  // Copilot review follow-up (mesh-client.ts): a malformed / headerless
  // "encrypted" frame that arrives before a session/KNOCK exists must be
  // dropped at the ratchet-header check, NOT parked in the pre-KNOCK buffer.
  // Otherwise an unauthenticated sender could consume per-peer buffer capacity
  // (preKnockBufferSize) with frames it can never decrypt until TTL eviction,
  // and the frame would only fail closed when the buffer is later drained.
  test("headerless encrypted frame is dropped before pre-KNOCK buffering, not buffered", async () => {
    // preKnockBufferSize > 0 => buffering is enabled; the fix must still refuse
    // to buffer a frame that carries no ratchet header.
    const client = makeClient({ preKnockBufferSize: 5 });
    const errors: Array<{ kind: string; from: string; detail: string }> = [];
    client.onError((kind, from, detail) => errors.push({ kind, from, detail }));

    await client.connect();

    const peer = "did:mesh:cccccccccccccccccccccccccccccccc";
    // Encrypted (no plaintext flag), no session, no KNOCK — and NO `header`.
    const frame: Record<string, unknown> = {
      v: 1,
      type: "message",
      from: peer,
      to: SELF_DID,
      id: "headerless-1",
      ts: new Date().toISOString(),
      ciphertext: btoa(JSON.stringify({ x: 1 })),
    };
    lastMockWs!.simulateFrame(frame);
    await tick();

    // Dropped immediately with the ratchet-header error...
    expect(
      errors.some((e) => e.kind === "decrypt" && e.from === peer && /ratchet header/.test(e.detail)),
    ).toBe(true);
    // ...and NOT parked in the pre-KNOCK buffer.
    expect(internals(client).preKnockBuffer.has(peer)).toBe(false);
  });

  // ── Downgrade-after-teardown latch (review finding, mesh-client.ts:801) ──
  //
  // Gating the plaintext branch on a live `session.channel` alone is not
  // sufficient: any path that DELETES the session re-opens the gate for a peer
  // that was already cryptographically verified. Two such paths exist, so the
  // gate additionally latches on `e2eVerifiedSet`.

  /** Well-formed ratchet header, garbage ciphertext — passes the header check,
   *  then fails inside channel.receive() and trips the Gap-G3 desync teardown. */
  function garbageCiphertextFrame(from: string, id: string): Record<string, unknown> {
    return {
      v: 1,
      type: "message",
      from,
      to: SELF_DID,
      id,
      ts: new Date().toISOString(),
      header: { dh: btoa("well-formed-but-wrong"), pn: 0, n: 0 },
      ciphertext: btoa("garbage"),
    };
  }

  // Vector A — two-frame sequence: force a ratchet desync (which tears the
  // session down), then downgrade on the following frame.
  test("two-frame desync must not re-open the plaintext gate for an E2E-verified peer", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ payload: unknown; isPlaintext: boolean }> = [];
    const errors: Array<{ kind: string }> = [];
    client.onMessage((_from, payload, isPlaintext) => received.push({ payload, isPlaintext }));
    client.onError((kind) => errors.push({ kind }));

    await client.connect();
    injectEncryptedSession(client, peer);
    internals(client).e2eVerifiedSet.add(peer);

    // Frame 1 — desync tears down the session (verified below).
    lastMockWs!.simulateFrame(garbageCiphertextFrame(peer, "desync-1"));
    await tick();
    expect(errors).toContainEqual({ kind: "session_desync" });
    expect(internals(client).sessions.get(peer)).toBeUndefined();

    // Frame 2 — the gate must stay closed even though the session is gone.
    lastMockWs!.simulateFrame(plaintextFrame(peer, { cmd: "transfer", amount: 999999 }));
    await tick();

    expect(received).toHaveLength(0);
  });

  // Vector B — one frame: `knock_reject` is dispatched without authentication
  // and calls closeSession(frame.from), so a malicious relay can delete the
  // session without any crypto interaction at all.
  test("injected knock_reject must not re-open the plaintext gate for an E2E-verified peer", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ payload: unknown; isPlaintext: boolean }> = [];
    client.onMessage((_from, payload, isPlaintext) => received.push({ payload, isPlaintext }));

    await client.connect();
    injectEncryptedSession(client, peer);
    internals(client).e2eVerifiedSet.add(peer);

    lastMockWs!.simulateFrame({ v: 1, type: "knock_reject", from: peer, to: SELF_DID });
    await tick();
    expect(internals(client).sessions.get(peer)).toBeUndefined();

    lastMockWs!.simulateFrame(plaintextFrame(peer, { cmd: "exfiltrate" }));
    await tick();

    expect(received).toHaveLength(0);
  });

  // End-to-end form of the latch: the peer is marked E2E-verified by genuinely
  // decrypting a frame through the production code path (not by seeding the
  // set), and is then permanently refused plaintext after a teardown.
  test("a peer latched by a real decrypt is refused plaintext after session teardown", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ payload: unknown; isPlaintext: boolean }> = [];
    client.onMessage((_from, payload, isPlaintext) => received.push({ payload, isPlaintext }));

    await client.connect();

    // 1. A genuine encrypted frame decrypts -> sets e2eVerifiedSet via real code.
    injectEncryptedSession(client, peer, () =>
      new TextEncoder().encode(JSON.stringify({ text: "hello-encrypted" })),
    );
    lastMockWs!.simulateFrame(encryptedFrame(peer, { ciphertext: "opaque" }));
    await tick();
    expect(received).toEqual([{ payload: { text: "hello-encrypted" }, isPlaintext: false }]);
    expect(internals(client).e2eVerifiedSet.has(peer)).toBe(true);

    // 2. Tear the session down out-of-band.
    client.closeSession(peer);
    expect(internals(client).sessions.get(peer)).toBeUndefined();

    // 3. Plaintext is still refused — the latch outlives the session.
    lastMockWs!.simulateFrame(plaintextFrame(peer, { cmd: "downgrade" }));
    await tick();

    expect(received).toHaveLength(1); // still only the decrypted message
  });

  // The latch must key on E2E verification, not on "has ever had a session":
  // an allow-listed peer that was never cryptographically verified keeps working.
  test("no regression: never-verified allow-listed peer still receives plaintext after a teardown", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: Array<{ payload: unknown; isPlaintext: boolean }> = [];
    client.onMessage((_from, payload, isPlaintext) => received.push({ payload, isPlaintext }));

    await client.connect();

    // Session exists but no frame was ever decrypted -> not E2E-verified.
    injectEncryptedSession(client, peer);
    client.closeSession(peer);
    expect(internals(client).e2eVerifiedSet.has(peer)).toBe(false);

    lastMockWs!.simulateFrame(plaintextFrame(peer, { text: "legit-plaintext" }));
    await tick();

    expect(received).toEqual([{ payload: { text: "legit-plaintext" }, isPlaintext: true }]);
  });
});
