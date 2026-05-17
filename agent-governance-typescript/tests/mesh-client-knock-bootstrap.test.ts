// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for receiver-side X3DH auto-bootstrap from KNOCK frames.
 *
 * Mirrors vendored agentmesh-sdk patch #4b: when a peer sends a KNOCK with
 * the X3DH `establishment` data embedded, the receiver auto-creates the
 * responder side of the SecureChannel before any encrypted messages arrive.
 *
 * Without this, the receiver throws "No encrypted session" the first time
 * a ciphertext arrives because acceptSession() was never called.
 *
 * Backwards-compatible: if a knock arrives without `establishment` (older
 * peers), behavior is unchanged — caller must invoke acceptSession() manually.
 */

import { MeshClient, type MeshClientOptions } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
import { SecureChannel } from "../src/encryption/channel";
import { ed25519 } from "@noble/curves/ed25519";

class MockWebSocket {
  sent: Array<Record<string, unknown>> = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onclose: ((event?: { code?: number }) => void) | null = null;
  closed = false;

  constructor(_url: string) {
    queueMicrotask(() => { if (this.onopen) this.onopen(); });
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(): void {
    this.closed = true;
    if (this.onclose) this.onclose({ code: 1000 });
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
  const km = new X3DHKeyManager(priv, pub);
  km.generateSignedPreKey();
  return km;
}

function makeClient(did: string, overrides?: Partial<MeshClientOptions>): MeshClient {
  return new MeshClient({
    relayUrl: "http://localhost:8080",
    registryUrl: "http://localhost:8081",
    autoRegister: false,
    keyManager: makeKeyManager(),
    agentDid: did,
    autoReconnect: false,
    wsFactory: mockWsFactory,
    ...overrides,
  });
}

describe("MeshClient KNOCK auto-bootstrap (G1)", () => {
  beforeEach(() => { lastMockWs = null; });

  test("sender embeds establishment in knock frame", async () => {
    const km = makeKeyManager();
    const sender = new MeshClient({
      relayUrl: "http://localhost:8080",
      registryUrl: "http://localhost:8081",
      autoRegister: false,
      keyManager: km,
      agentDid: "did:agentmesh:alice",
      autoReconnect: false,
      wsFactory: mockWsFactory,
    });
    await sender.connect();

    const peerKm = makeKeyManager();
    const bundle = peerKm.getPublicBundle();

    await sender.establishSession("did:agentmesh:bob", bundle);

    const aliceWs = lastMockWs!;
    const knockFrame = aliceWs.sent.find((f) => f.type === "knock");
    expect(knockFrame).toBeDefined();
    expect(knockFrame!.establishment).toBeDefined();
    const est = knockFrame!.establishment as Record<string, unknown>;
    expect(typeof est.ik).toBe("string");
    expect(typeof est.ek).toBe("string");
  });

  test("receiver auto-creates responder session from embedded establishment", async () => {
    // Build an establishment the way a real sender would.
    const senderKm = makeKeyManager();
    const receiverKm = makeKeyManager();
    const peerBundle = receiverKm.getPublicBundle();
    const [, establishment] = SecureChannel.createSender(
      senderKm,
      peerBundle,
      new TextEncoder().encode("did:agentmesh:alice|did:agentmesh:bob"),
    );

    const receiver = new MeshClient({
      relayUrl: "http://localhost:8080",
      registryUrl: "http://localhost:8081",
      autoRegister: false,
      keyManager: receiverKm,
      agentDid: "did:agentmesh:bob",
      autoReconnect: false,
      wsFactory: mockWsFactory,
    });
    receiver.onKnock(async () => true);
    await receiver.connect();

    expect(receiver.getSession("did:agentmesh:alice")).toBeUndefined();

    // Simulate the relay pushing the knock with establishment.
    lastMockWs!.simulateFrame({
      v: 1,
      type: "knock",
      from: "did:agentmesh:alice",
      to: "did:agentmesh:bob",
      id: "knock-1",
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
      establishment: {
        ik: Buffer.from(establishment.initiatorIdentityKey).toString("base64"),
        ek: Buffer.from(establishment.ephemeralPublicKey).toString("base64"),
        ...(establishment.usedOneTimeKeyId !== undefined
          ? { otk: establishment.usedOneTimeKeyId }
          : {}),
      },
    });

    // Yield so the async knock handler runs.
    await new Promise((r) => setTimeout(r, 10));

    const session = receiver.getSession("did:agentmesh:alice");
    expect(session).toBeDefined();
    expect(session!.channel).not.toBeNull();
    expect(session!.isPlaintext).toBe(false);
  });

  test("knock without establishment keeps legacy behavior (no auto-session)", async () => {
    const receiver = makeClient("did:agentmesh:bob");
    receiver.onKnock(async () => true);
    await receiver.connect();

    lastMockWs!.simulateFrame({
      v: 1,
      type: "knock",
      from: "did:agentmesh:legacy-peer",
      to: "did:agentmesh:bob",
      id: "knock-2",
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
    });

    await new Promise((r) => setTimeout(r, 10));

    // No auto-session because no establishment was provided.
    expect(receiver.getSession("did:agentmesh:legacy-peer")).toBeUndefined();
    // But the knock was still accepted (knock_accept frame was sent).
    expect(lastMockWs!.sent.find((f) => f.type === "knock_accept")).toBeDefined();
  });

  test("malformed establishment fires onError and rejects knock", async () => {
    const receiver = makeClient("did:agentmesh:bob");
    receiver.onKnock(async () => true);
    const errors: Array<{ kind: string; detail: string }> = [];
    receiver.onError((kind, _from, detail) => errors.push({ kind, detail }));
    await receiver.connect();

    lastMockWs!.simulateFrame({
      v: 1,
      type: "knock",
      from: "did:agentmesh:attacker",
      to: "did:agentmesh:bob",
      id: "knock-3",
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
      establishment: { ik: 123, ek: "valid" },
    });

    await new Promise((r) => setTimeout(r, 10));

    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].kind).toBe("knock");
    // Should have rejected the knock since bootstrap failed.
    expect(lastMockWs!.sent.find((f) => f.type === "knock_reject")).toBeDefined();
    expect(receiver.getSession("did:agentmesh:attacker")).toBeUndefined();
  });

  test("end-to-end: KNOCK auto-bootstrap → first encrypted message decrypts", async () => {
    // Full happy-path: alice establishes, bob auto-bootstraps from the knock,
    // alice sends an encrypted message, bob decrypts it without ever calling
    // acceptSession().
    const aliceKm = makeKeyManager();
    const bobKm = makeKeyManager();
    const bobBundle = bobKm.getPublicBundle();

    const alice = new MeshClient({
      relayUrl: "http://localhost:8080",
      registryUrl: "http://localhost:8081",
      autoRegister: false,
      keyManager: aliceKm,
      agentDid: "did:agentmesh:alice",
      autoReconnect: false,
      wsFactory: mockWsFactory,
    });
    await alice.connect();
    const aliceWs = lastMockWs!;
    await alice.establishSession("did:agentmesh:bob", bobBundle);

    const bob = new MeshClient({
      relayUrl: "http://localhost:8080",
      registryUrl: "http://localhost:8081",
      autoRegister: false,
      keyManager: bobKm,
      agentDid: "did:agentmesh:bob",
      autoReconnect: false,
      wsFactory: mockWsFactory,
    });
    bob.onKnock(async () => true);
    const decoded: Array<{ from: string; payload: unknown }> = [];
    bob.onMessage((from, payload) => decoded.push({ from, payload }));
    await bob.connect();
    const bobWs = lastMockWs!;

    // Replay the knock alice sent into bob's transport.
    const knockFrame = aliceWs.sent.find((f) => f.type === "knock");
    expect(knockFrame).toBeDefined();
    bobWs.simulateFrame(knockFrame!);
    await new Promise((r) => setTimeout(r, 10));

    // Bob should have a session now without ever calling acceptSession().
    const bobSession = bob.getSession("did:agentmesh:alice");
    expect(bobSession).toBeDefined();
    expect(bobSession!.channel).not.toBeNull();

    // Alice sends an encrypted message; replay it into bob.
    await alice.send("did:agentmesh:bob", { hello: "from alice" });
    const messageFrame = aliceWs.sent.find((f) => f.type === "message");
    expect(messageFrame).toBeDefined();
    bobWs.simulateFrame(messageFrame!);
    await new Promise((r) => setTimeout(r, 10));

    expect(decoded).toEqual([
      { from: "did:agentmesh:alice", payload: { hello: "from alice" } },
    ]);
  });
});
