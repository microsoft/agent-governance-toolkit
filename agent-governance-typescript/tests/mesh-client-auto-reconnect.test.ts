// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for MeshClient auto-reconnect on transport drop.
 *
 * Mirrors vendored agentmesh-sdk patch #9: when the WebSocket closes for
 * any non-client-initiated reason (network blip, relay restart, infra
 * upgrade, AKS node OOM-evict), the client schedules a reconnect with
 * exponential backoff, capped at 60s, and retries forever by default.
 *
 * Tests use small real delays (5–50ms) rather than fake timers because
 * the WebSocket mock relies on queueMicrotask, which doesn't compose
 * cleanly with jest.useFakeTimers.
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
  failOnConnect: boolean;

  constructor(_url: string, failOnConnect = false) {
    this.failOnConnect = failOnConnect;
    queueMicrotask(() => {
      if (this.failOnConnect) {
        if (this.onerror) this.onerror({ message: "ECONNREFUSED" });
        if (this.onclose) this.onclose({ code: 1006 });
      } else if (this.onopen) {
        this.onopen();
      }
    });
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(code = 1000): void {
    this.closed = true;
    if (this.onclose) this.onclose({ code });
  }

  simulateServerClose(code = 1006): void {
    this.closed = true;
    if (this.onclose) this.onclose({ code });
  }
}

const createdSockets: MockWebSocket[] = [];
function freshFactory(): (url: string) => WebSocket {
  return (url: string): WebSocket => {
    const ws = new MockWebSocket(url);
    createdSockets.push(ws);
    return ws as unknown as WebSocket;
  };
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
    agentDid: "did:agentmesh:test",
    wsFactory: freshFactory(),
    ...overrides,
  });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("MeshClient auto-reconnect (G2)", () => {
  beforeEach(() => {
    createdSockets.length = 0;
  });

  test("on server close, schedules reconnect and reconnects", async () => {
    const client = makeClient({ reconnectBaseDelayMs: 10, reconnectMaxDelayMs: 50 });
    await client.connect();
    expect(createdSockets).toHaveLength(1);

    createdSockets[0].simulateServerClose(1006);
    expect(client.isConnected).toBe(false);

    // First retry: base 10ms * 1 = 10ms (with jitter, up to ~12ms).
    await sleep(50);

    expect(createdSockets.length).toBeGreaterThanOrEqual(2);
    expect(client.isConnected).toBe(true);

    await client.disconnect();
  });

  test("on client disconnect (close 1000), does NOT reconnect", async () => {
    const client = makeClient({ reconnectBaseDelayMs: 10 });
    await client.connect();
    expect(createdSockets).toHaveLength(1);

    await client.disconnect();
    await sleep(100);

    expect(createdSockets).toHaveLength(1);
    expect(client.isConnected).toBe(false);
  });

  test("autoReconnect:false disables the loop", async () => {
    const client = makeClient({ autoReconnect: false, reconnectBaseDelayMs: 10 });
    await client.connect();
    createdSockets[0].simulateServerClose(1006);

    await sleep(100);

    expect(createdSockets).toHaveLength(1);
    expect(client.isConnected).toBe(false);
  });

  test("respects maxReconnectAttempts and surfaces error after exhaustion", async () => {
    let attempt = 0;
    const failingFactory = (url: string): WebSocket => {
      attempt++;
      const ws = new MockWebSocket(url, attempt >= 2);
      createdSockets.push(ws);
      return ws as unknown as WebSocket;
    };

    const client = new MeshClient({
      relayUrl: "http://localhost:8080",
      registryUrl: "http://localhost:8081",
      autoRegister: false,
      keyManager: makeKeyManager(),
      agentDid: "did:agentmesh:test",
      wsFactory: failingFactory,
      reconnectBaseDelayMs: 5,
      reconnectMaxDelayMs: 10,
      maxReconnectAttempts: 2,
    });

    const errors: string[] = [];
    client.onError((_kind, _from, detail) => errors.push(detail));

    await client.connect();
    expect(client.isConnected).toBe(true);

    createdSockets[0].simulateServerClose(1006);
    // Wait long enough for both retries to fail and the give-up message to fire.
    await sleep(200);

    const gaveUp = errors.some((e) => e.includes("auto-reconnect gave up"));
    expect(gaveUp).toBe(true);
    expect(client.isConnected).toBe(false);
  });

  test("disconnect() during pending reconnect cancels the timer", async () => {
    const client = makeClient({ reconnectBaseDelayMs: 5000 });
    await client.connect();
    createdSockets[0].simulateServerClose(1006);

    // Cancel before the reconnect timer fires.
    await client.disconnect();
    await sleep(50);

    expect(createdSockets).toHaveLength(1);
  });

  test("does not schedule a duplicate reconnect when already pending", async () => {
    // Two consecutive server closes shouldn't double-schedule.
    const client = makeClient({ reconnectBaseDelayMs: 50 });
    await client.connect();

    createdSockets[0].simulateServerClose(1006);
    // A second simulated close on the same (already-closed) socket is a no-op
    // logically — but we want to verify that even if a buggy server sent two
    // close events, only one reconnect timer is in flight.
    createdSockets[0].simulateServerClose(1006);

    await sleep(150);

    // Exactly one reconnect socket — total 2.
    expect(createdSockets).toHaveLength(2);

    await client.disconnect();
  });
});
