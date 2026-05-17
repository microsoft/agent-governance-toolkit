// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for MeshClient event hooks: onError, onDisconnect, onE2EVerified.
 *
 * These hooks were added to align MeshClient's observer surface with the
 * AzureClaw vendored AgentMesh SDK so consumers can swap providers
 * (vendored ↔ AGT) behind a single transport interface.
 *
 * The hooks are pure additions — no behaviour change to existing flows.
 * Existing tests in mesh-client-reconnect.test.ts and encryption.test.ts
 * cover the no-handler-registered cases.
 */

import { MeshClient, type MeshClientOptions } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
import { ed25519 } from "@noble/curves/ed25519";

// ── Mock WebSocket ───────────────────────────────────────────────

class MockWebSocket {
  sent: Array<Record<string, unknown>> = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onclose: ((event?: { code?: number }) => void) | null = null;
  closed = false;

  constructor(_url: string) {
    queueMicrotask(() => {
      if (this.onopen) this.onopen();
    });
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(): void {
    this.closed = true;
    if (this.onclose) this.onclose({ code: 1000 });
  }

  /** Simulate the relay closing the socket (server-side disconnect). */
  simulateServerClose(code = 1006): void {
    this.closed = true;
    if (this.onclose) this.onclose({ code });
  }

  /** Simulate the WebSocket emitting an error event mid-stream. */
  simulateError(detail = "network blip"): void {
    if (this.onerror) this.onerror({ message: detail });
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

// ── onDisconnect ─────────────────────────────────────────────────

describe("MeshClient.onDisconnect", () => {
  beforeEach(() => {
    lastMockWs = null;
  });

  test("fires with reason='client' when caller calls disconnect()", async () => {
    const client = makeClient();
    const events: Array<{ reason: string; code?: number }> = [];
    client.onDisconnect((reason, code) => events.push({ reason, code }));

    await client.connect();
    await client.disconnect();

    // disconnect() calls ws.close() which triggers onclose with code 1000
    // (Normal Closure) — observable as reason="client".
    expect(events).toEqual([{ reason: "client", code: 1000 }]);
  });

  test("fires with reason='server' when relay closes the socket", async () => {
    const client = makeClient();
    const events: Array<{ reason: string; code?: number }> = [];
    client.onDisconnect((reason, code) => events.push({ reason, code }));

    await client.connect();
    lastMockWs!.simulateServerClose(1006);

    expect(events).toEqual([{ reason: "server", code: 1006 }]);
  });

  test("fires with reason='client' when relay closes with code 1000", async () => {
    const client = makeClient();
    const events: Array<{ reason: string; code?: number }> = [];
    client.onDisconnect((reason, code) => events.push({ reason, code }));

    await client.connect();
    lastMockWs!.simulateServerClose(1000);

    expect(events).toEqual([{ reason: "client", code: 1000 }]);
  });

  test("multiple handlers all fire; thrown handler errors are swallowed", async () => {
    const client = makeClient();
    const events: string[] = [];
    client.onDisconnect(() => events.push("a"));
    client.onDisconnect(() => {
      throw new Error("buggy handler");
    });
    client.onDisconnect(() => events.push("c"));

    await client.connect();
    lastMockWs!.simulateServerClose(1006);

    expect(events).toEqual(["a", "c"]);
  });
});

// ── onError ──────────────────────────────────────────────────────

describe("MeshClient.onError", () => {
  beforeEach(() => {
    lastMockWs = null;
  });

  test("fires on ws error after connection is established", async () => {
    const client = makeClient();
    const events: Array<{ kind: string; from: string; detail: string }> = [];
    client.onError((kind, from, detail) => events.push({ kind, from, detail }));

    await client.connect();
    lastMockWs!.simulateError("connection reset by peer");

    expect(events.length).toBe(1);
    expect(events[0].kind).toBe("ws");
    expect(events[0].from).toBe("did:agentmesh:test-agent");
    expect(events[0].detail).toContain("connection reset");
  });

  test("fires on decrypt path when no session exists for encrypted frame", async () => {
    // With pre-KNOCK buffer disabled (size=0), encrypted-before-session frames
    // fall through to the legacy fire-decrypt-and-drop path. The buffered
    // behaviour is covered separately in mesh-client-pre-knock-buffer.test.ts.
    const client = makeClient({ preKnockBufferSize: 0 });
    const errors: Array<{ kind: string; from: string }> = [];
    client.onError((kind, from) => errors.push({ kind, from }));

    await client.connect();
    // Simulate an encrypted frame from a peer we never established a session with.
    lastMockWs!.onmessage!({
      data: JSON.stringify({
        v: 1,
        type: "message",
        from: "did:agentmesh:unknown-peer",
        id: "msg-1",
        ciphertext: "AAAA",
        header: { dh: "AAAA", pn: 0, n: 0 },
      }),
    });

    expect(errors.length).toBe(1);
    expect(errors[0].kind).toBe("decrypt");
    expect(errors[0].from).toBe("did:agentmesh:unknown-peer");
  });
});

// ── onE2EVerified ────────────────────────────────────────────────

describe("MeshClient.onE2EVerified", () => {
  beforeEach(() => {
    lastMockWs = null;
  });

  test("does NOT fire for plaintext peers (legacy path)", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:plain"] });
    const verified: string[] = [];
    client.onE2EVerified((amid) => verified.push(amid));

    await client.connect();
    // Simulate a plaintext frame from the peer.
    const payload = btoa(JSON.stringify({ hello: "world" }));
    lastMockWs!.onmessage!({
      data: JSON.stringify({
        v: 1,
        type: "message",
        from: "did:agentmesh:plain",
        id: "msg-1",
        ciphertext: payload,
        plaintext: true,
      }),
    });

    expect(verified).toEqual([]);
  });

  test("registers handler without throwing (encrypted path covered by integration tests)", async () => {
    // The encrypted path requires full X3DH session setup which is exercised
    // end-to-end in encryption.test.ts. Here we just validate registration
    // surface and that no-encrypted-frames-yet means no spurious fires.
    const client = makeClient();
    const verified: string[] = [];
    client.onE2EVerified((amid) => verified.push(amid));

    await client.connect();

    expect(verified).toEqual([]);
  });
});
