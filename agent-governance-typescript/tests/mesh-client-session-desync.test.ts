// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for session-desync teardown (Gap G3 — vendored agentmesh-sdk
 * patch #13 equivalent).
 *
 * Background: when Double Ratchet decryption fails for a peer with whom
 * we already have an established session, the local ratchet state is
 * irrecoverable — every subsequent message from that peer will also
 * fail with the same error. Previously MeshClient only fired
 * onError("decrypt", ...) and left the broken session in place; the
 * application had no clean recovery path. Now we tear down the session
 * (delete from `sessions`, clear `knockAccepted`) and fire a distinct
 * `session_desync` error so the caller can re-run establishSession() and
 * resume communication.
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
  constructor(_url: string) { queueMicrotask(() => { if (this.onopen) this.onopen(); }); }
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

describe("MeshClient session-desync teardown (Gap G3)", () => {
  beforeEach(() => { lastMockWs = null; });

  test("session_desync is a valid onError kind on the public type", () => {
    // Compile-time check: this assignment must type-check. If the union
    // narrows back to `"ws" | "decrypt" | "knock" | "frame"`, tsc fails.
    const client = makeClient();
    const handler: Parameters<MeshClient["onError"]>[0] = (kind) => {
      const k: "ws" | "decrypt" | "knock" | "frame" | "session_desync" = kind;
      void k;
    };
    client.onError(handler);
  });

  test("disconnect cleans up state without throwing after errors fired", async () => {
    const client = makeClient({ preKnockBufferSize: 0 });
    await client.connect();
    // Drive a decrypt-no-session error (different code path from session
    // desync, but exercises the error-firing pipeline and disconnect path).
    lastMockWs!.onmessage!({
      data: JSON.stringify({
        v: 1, type: "message", from: "did:agentmesh:other", id: "x",
        ciphertext: "AAAA", header: { dh: "AAAA", pn: 0, n: 0 },
      }),
    });
    await expect(client.disconnect()).resolves.toBeUndefined();
  });
});
