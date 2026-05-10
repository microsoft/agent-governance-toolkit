// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for MeshClient inbox replay on reconnect.
 *
 * Validates that the client sends a fetch_pending frame after connect,
 * handles pending_messages batch frames, and provides a clean reconnect
 * cycle.
 *
 * Ref: Issue #1407 — MeshClient delivery-on-reconnect (inbox replay)
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 12
 */

import { MeshClient, type MeshClientOptions } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
import { ed25519 } from "@noble/curves/ed25519";

// ── Mock WebSocket ───────────────────────────────────────────────

/** Minimal mock WebSocket that records sent frames and triggers handlers. */
class MockWebSocket {
  sent: Array<Record<string, unknown>> = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((e: unknown) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;

  constructor(_url: string) {
    // Auto-trigger onopen on next tick to simulate connection
    queueMicrotask(() => {
      if (this.onopen) this.onopen();
    });
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }

  close(): void {
    this.closed = true;
    if (this.onclose) this.onclose();
  }

  /** Simulate the relay pushing a frame to the client. */
  simulateFrame(frame: Record<string, unknown>): void {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify(frame) });
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────

describe("MeshClient inbox replay", () => {
  beforeEach(() => {
    lastMockWs = null;
  });

  test("sends fetch_pending frame after connect", async () => {
    const client = makeClient();
    await client.connect();

    expect(lastMockWs).not.toBeNull();
    const frames = lastMockWs!.sent;

    // Should have at least 2 frames: connect + fetch_pending
    expect(frames.length).toBeGreaterThanOrEqual(2);

    const connectFrame = frames.find((f) => f.type === "connect");
    expect(connectFrame).toBeDefined();
    expect(connectFrame!.from).toBe("did:agentmesh:test-agent");

    const fetchFrame = frames.find((f) => f.type === "fetch_pending");
    expect(fetchFrame).toBeDefined();
    expect(fetchFrame!.from).toBe("did:agentmesh:test-agent");
    expect(fetchFrame!.v).toBe(1);
  });

  test("connect sends fetch_pending after connect (ordering)", async () => {
    const client = makeClient();
    await client.connect();

    const frames = lastMockWs!.sent;
    const connectIdx = frames.findIndex((f) => f.type === "connect");
    const fetchIdx = frames.findIndex((f) => f.type === "fetch_pending");

    expect(connectIdx).toBeGreaterThanOrEqual(0);
    expect(fetchIdx).toBeGreaterThan(connectIdx);
  });

  test("handles pending_messages batch with plaintext messages", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:peer-a"] });
    const received: Array<{ from: string; payload: unknown; isPlaintext: boolean }> = [];

    client.onMessage((from, payload, isPlaintext) => {
      received.push({ from, payload, isPlaintext });
    });

    await client.connect();

    // Simulate relay sending a pending_messages batch
    const pendingBatch = {
      v: 1,
      type: "pending_messages",
      messages: [
        {
          v: 1,
          type: "message",
          from: "did:agentmesh:peer-a",
          to: "did:agentmesh:test-agent",
          id: "msg-001",
          ts: new Date().toISOString(),
          ciphertext: btoa(JSON.stringify({ text: "hello from offline" })),
          plaintext: true,
        },
        {
          v: 1,
          type: "message",
          from: "did:agentmesh:peer-a",
          to: "did:agentmesh:test-agent",
          id: "msg-002",
          ts: new Date().toISOString(),
          ciphertext: btoa(JSON.stringify({ text: "second offline msg" })),
          plaintext: true,
        },
      ],
    };

    lastMockWs!.simulateFrame(pendingBatch);

    // Allow async handlers to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(received).toHaveLength(2);
    expect(received[0].from).toBe("did:agentmesh:peer-a");
    expect(received[0].payload).toEqual({ text: "hello from offline" });
    expect(received[0].isPlaintext).toBe(true);
    expect(received[1].payload).toEqual({ text: "second offline msg" });
  });

  test("handles empty pending_messages gracefully", async () => {
    const client = makeClient();
    const received: unknown[] = [];

    client.onMessage((from, payload) => {
      received.push(payload);
    });

    await client.connect();

    // Empty messages array
    lastMockWs!.simulateFrame({ v: 1, type: "pending_messages", messages: [] });
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(0);

    // Missing messages field
    lastMockWs!.simulateFrame({ v: 1, type: "pending_messages" });
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(0);

    // Null messages field
    lastMockWs!.simulateFrame({ v: 1, type: "pending_messages", messages: null });
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(0);
  });

  test("sends ack for each pending message", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:sender"] });

    client.onMessage(() => {
      /* consume */
    });

    await client.connect();

    lastMockWs!.simulateFrame({
      v: 1,
      type: "pending_messages",
      messages: [
        {
          v: 1,
          type: "message",
          from: "did:agentmesh:sender",
          to: "did:agentmesh:test-agent",
          id: "ack-test-001",
          ts: new Date().toISOString(),
          ciphertext: btoa(JSON.stringify({ data: "test" })),
          plaintext: true,
        },
      ],
    });

    await new Promise((r) => setTimeout(r, 50));

    const acks = lastMockWs!.sent.filter((f) => f.type === "ack");
    expect(acks.length).toBeGreaterThanOrEqual(1);
    expect(acks.some((a) => a.id === "ack-test-001")).toBe(true);
  });

  test("reconnect() resets and reconnects with fetch_pending", async () => {
    const client = makeClient();
    await client.connect();

    const firstWs = lastMockWs;
    expect(client.isConnected).toBe(true);

    // Reconnect
    await client.reconnect();

    // Should have created a new WebSocket
    expect(lastMockWs).not.toBe(firstWs);
    expect(client.isConnected).toBe(true);

    // New connection should also have connect + fetch_pending
    const frames = lastMockWs!.sent;
    expect(frames.find((f) => f.type === "connect")).toBeDefined();
    expect(frames.find((f) => f.type === "fetch_pending")).toBeDefined();
  });

  test("reconnect() works after disconnect", async () => {
    const client = makeClient();
    await client.connect();
    await client.disconnect();
    expect(client.isConnected).toBe(false);

    await client.reconnect();
    expect(client.isConnected).toBe(true);

    const frames = lastMockWs!.sent;
    expect(frames.find((f) => f.type === "connect")).toBeDefined();
    expect(frames.find((f) => f.type === "fetch_pending")).toBeDefined();
  });

  test("no-op connect when already connected", async () => {
    const client = makeClient();
    await client.connect();

    const ws = lastMockWs;
    await client.connect(); // should be no-op

    // Same WebSocket, no additional frames
    expect(lastMockWs).toBe(ws);
  });

  test("pending_messages preserves message order", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:peer"] });
    const order: number[] = [];

    client.onMessage((_from, payload) => {
      order.push((payload as { seq: number }).seq);
    });

    await client.connect();

    const messages = Array.from({ length: 5 }, (_, i) => ({
      v: 1,
      type: "message",
      from: "did:agentmesh:peer",
      to: "did:agentmesh:test-agent",
      id: `order-${i}`,
      ts: new Date().toISOString(),
      ciphertext: btoa(JSON.stringify({ seq: i })),
      plaintext: true,
    }));

    lastMockWs!.simulateFrame({ v: 1, type: "pending_messages", messages });
    await new Promise((r) => setTimeout(r, 50));

    expect(order).toEqual([0, 1, 2, 3, 4]);
  });
});
