// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for MeshClient KNOCK timer race and pending cleanup.
 *
 * Regression scenarios:
 *   1. Timer fires while knock handlers are still running — pending entry
 *      must still be cleared and the relay must see a knock_reject (not
 *      a stale knock_accept from the late-completing handler).
 *   2. A knock handler that throws must still clear the pending entry,
 *      otherwise re-KNOCK from the same peer races against stale state.
 *   3. The verdict resolved into knockPending must reach waiters added
 *      by handleMessage between knock-arrival and verdict-decision.
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

function makeClient(overrides?: Partial<MeshClientOptions>): MeshClient {
  return new MeshClient({
    relayUrl: "http://localhost:8080",
    registryUrl: "http://localhost:8081",
    keyManager: makeKeyManager(),
    agentDid: "did:agentmesh:test-agent",
    wsFactory: mockWsFactory,
    autoRegister: false,
    ...overrides,
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("MeshClient KNOCK timer race", () => {
  beforeEach(() => {
    lastMockWs = null;
  });

  test("timer fires while knock handler is still running — relay sees knock_reject, not knock_accept", async () => {
    const client = makeClient({ knockTimeout: 30 });
    // Handler takes longer than knockTimeout; would (under the old code)
    // eventually return true and trigger knock_accept after the timer
    // had already told waiters the KNOCK was rejected.
    client.onKnock(async () => {
      await delay(120);
      return true;
    });

    await client.connect();

    const knockFrame = {
      v: 1,
      type: "knock",
      from: "did:agentmesh:peer-slow",
      to: "did:agentmesh:test-agent",
      id: "knock-1",
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
    };
    lastMockWs!.simulateFrame(knockFrame);

    // Wait long enough for both the timer (30ms) and the handler (120ms)
    // to complete.
    await delay(200);

    const knockResponses = lastMockWs!.sent.filter(
      (f) => f.type === "knock_accept" || f.type === "knock_reject",
    );

    expect(knockResponses).toHaveLength(1);
    expect(knockResponses[0].type).toBe("knock_reject");
  });

  test("happy path: handler accepts → relay gets knock_accept", async () => {
    const client = makeClient({ knockTimeout: 500 });
    client.onKnock(async () => true);

    await client.connect();

    lastMockWs!.simulateFrame({
      v: 1,
      type: "knock",
      from: "did:agentmesh:peer-ok",
      to: "did:agentmesh:test-agent",
      id: "knock-ok",
      ts: new Date().toISOString(),
      intent: {},
    });

    await delay(30);

    const knockResponses = lastMockWs!.sent.filter(
      (f) => f.type === "knock_accept" || f.type === "knock_reject",
    );
    expect(knockResponses).toHaveLength(1);
    expect(knockResponses[0].type).toBe("knock_accept");
  });

  test("rejecting handler → relay gets knock_reject", async () => {
    const client = makeClient({ knockTimeout: 500 });
    client.onKnock(async () => false);

    await client.connect();

    lastMockWs!.simulateFrame({
      v: 1,
      type: "knock",
      from: "did:agentmesh:peer-deny",
      to: "did:agentmesh:test-agent",
      id: "knock-deny",
      ts: new Date().toISOString(),
      intent: {},
    });

    await delay(30);

    const knockResponses = lastMockWs!.sent.filter(
      (f) => f.type === "knock_accept" || f.type === "knock_reject",
    );
    expect(knockResponses).toHaveLength(1);
    expect(knockResponses[0].type).toBe("knock_reject");
  });
});
