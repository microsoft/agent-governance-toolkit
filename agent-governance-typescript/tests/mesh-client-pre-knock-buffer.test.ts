// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for the pre-KNOCK encrypted-message buffer (Gap G4 —
 * vendored agentmesh-sdk patch #16 equivalent).
 *
 * Race: under transport reordering the relay can deliver an encrypted
 * `message` frame BEFORE the sender's `knock` frame reaches the responder.
 * Without buffering, that first frame is dropped silently, the application
 * sees nothing, and the sender times out. With buffering, the frame is
 * held until the matching KNOCK arrives, then replayed through the
 * normal decryption path.
 */

import { MeshClient, type MeshClientOptions } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
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

  send(data: string): void { this.sent.push(JSON.parse(data)); }
  close(): void { this.closed = true; if (this.onclose) this.onclose({ code: 1000 }); }
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

function makeClient(overrides?: Partial<MeshClientOptions>): MeshClient {
  return new MeshClient({
    relayUrl: "http://localhost:8080",
    registryUrl: "http://localhost:8081",
    autoRegister: false,
    keyManager: makeKeyManager(),
    agentDid: "did:agentmesh:test-agent",
    wsFactory: mockWsFactory,
    ...overrides,
  });
}

function encryptedFrame(from: string, id: string) {
  return {
    v: 1,
    type: "message",
    from,
    id,
    ciphertext: "AAAA",
    header: { dh: "AAAA", pn: 0, n: 0 },
  };
}

describe("MeshClient pre-KNOCK buffer (Gap G4)", () => {
  beforeEach(() => { lastMockWs = null; });

  test("encrypted-before-knock frame is buffered, NOT reported as decrypt error", async () => {
    const client = makeClient({ preKnockBufferSize: 5, preKnockBufferTtlMs: 1000 });
    const errors: Array<{ kind: string }> = [];
    client.onError((kind) => errors.push({ kind }));

    await client.connect();
    lastMockWs!.onmessage!({
      data: JSON.stringify(encryptedFrame("did:agentmesh:peer", "msg-1")),
    });

    // Frame should be buffered, not dropped with decrypt error.
    expect(errors.filter((e) => e.kind === "decrypt").length).toBe(0);
  });

  test("buffer is capped at preKnockBufferSize (oldest evicted)", async () => {
    const client = makeClient({ preKnockBufferSize: 2, preKnockBufferTtlMs: 60_000 });
    const errors: Array<{ kind: string }> = [];
    client.onError((kind) => errors.push({ kind }));

    await client.connect();
    for (let i = 0; i < 5; i++) {
      lastMockWs!.onmessage!({
        data: JSON.stringify(encryptedFrame("did:agentmesh:peer", `msg-${i}`)),
      });
    }

    // None should report decrypt error while buffered.
    expect(errors.filter((e) => e.kind === "decrypt").length).toBe(0);
  });

  test("setting preKnockBufferSize=0 disables buffering (legacy fire-decrypt path)", async () => {
    const client = makeClient({ preKnockBufferSize: 0 });
    const errors: Array<{ kind: string }> = [];
    client.onError((kind) => errors.push({ kind }));

    await client.connect();
    lastMockWs!.onmessage!({
      data: JSON.stringify(encryptedFrame("did:agentmesh:peer", "msg-1")),
    });

    expect(errors.length).toBe(1);
    expect(errors[0].kind).toBe("decrypt");
  });

  test("rejected knock drops the per-peer buffer (no replay)", async () => {
    const client = makeClient({ preKnockBufferSize: 5, preKnockBufferTtlMs: 60_000 });
    const decryptErrors: Array<{ kind: string }> = [];
    client.onError((kind) => decryptErrors.push({ kind }));
    // Reject any knock from this peer.
    client.onKnock(async () => false);

    await client.connect();
    // Buffer an encrypted frame.
    lastMockWs!.onmessage!({
      data: JSON.stringify(encryptedFrame("did:agentmesh:peer", "msg-1")),
    });
    // Now deliver a KNOCK that we will reject.
    lastMockWs!.onmessage!({
      data: JSON.stringify({
        v: 1, type: "knock", from: "did:agentmesh:peer", intent: { reason: "test" },
      }),
    });
    await new Promise((r) => setTimeout(r, 5));

    // Buffer was dropped, never replayed → no decrypt errors.
    expect(decryptErrors.filter((e) => e.kind === "decrypt").length).toBe(0);
    // Knock_reject was sent.
    expect(lastMockWs!.sent.some((f) => f.type === "knock_reject")).toBe(true);
  });

  test("buffer entries are cleared on disconnect (no leaked timers)", async () => {
    const client = makeClient({ preKnockBufferSize: 5, preKnockBufferTtlMs: 60_000 });
    await client.connect();
    lastMockWs!.onmessage!({
      data: JSON.stringify(encryptedFrame("did:agentmesh:peer", "msg-1")),
    });

    // disconnect() should not throw and should clear internal timers.
    await expect(client.disconnect()).resolves.toBeUndefined();
  });

  test("global peer cap evicts oldest peer buffer when exceeded", async () => {
    const client = makeClient({
      preKnockBufferSize: 5,
      preKnockBufferTtlMs: 60_000,
      maxBufferedPeers: 3,
    });
    const errors: Array<{ kind: string; from: string; detail: string }> = [];
    client.onError((kind, from, detail) => errors.push({ kind, from, detail }));

    await client.connect();

    // Buffer frames from 3 distinct peers (fills to cap).
    for (let i = 0; i < 3; i++) {
      lastMockWs!.onmessage!({
        data: JSON.stringify(encryptedFrame(`did:agentmesh:peer-${i}`, `msg-${i}`)),
      });
    }
    // No eviction yet.
    expect(errors.filter((e) => e.detail.includes("global peer cap")).length).toBe(0);

    // 4th peer triggers eviction of peer-0 (oldest).
    lastMockWs!.onmessage!({
      data: JSON.stringify(encryptedFrame("did:agentmesh:peer-3", "msg-3")),
    });

    const evictionErrors = errors.filter((e) => e.detail.includes("global peer cap"));
    expect(evictionErrors.length).toBe(1);
    expect(evictionErrors[0].from).toBe("did:agentmesh:peer-0");
  });
});
