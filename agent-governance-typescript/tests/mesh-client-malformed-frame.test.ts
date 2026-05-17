// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for MeshClient resilience to malformed relay frames.
 *
 * The WebSocket onmessage handler must not crash the client when the
 * relay sends non-JSON data or when async frame handling rejects.
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

  /** Push raw data into the onmessage handler — caller controls JSON validity. */
  pushRaw(data: string): void {
    if (this.onmessage) this.onmessage({ data });
  }

  /** Push a structured frame (always valid JSON). */
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

describe("MeshClient malformed frame handling", () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    lastMockWs = null;
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test("non-JSON frame does not throw out of the WebSocket dispatcher", async () => {
    const client = makeClient();
    await client.connect();

    expect(() => lastMockWs!.pushRaw("not json {{{")).not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("malformed frame"));
  });

  test("client survives malformed frame and processes subsequent valid frame", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:peer-a"] });
    const received: unknown[] = [];

    client.onMessage((from, payload) => {
      received.push({ from, payload });
    });

    await client.connect();

    lastMockWs!.pushRaw("garbage");
    lastMockWs!.pushRaw("{not even json}");

    lastMockWs!.simulateFrame({
      v: 1,
      type: "message",
      from: "did:agentmesh:peer-a",
      to: "did:agentmesh:test-agent",
      id: "msg-after-garbage",
      ts: new Date().toISOString(),
      ciphertext: btoa(JSON.stringify({ text: "recovered" })),
      plaintext: true,
    });

    await new Promise((r) => setTimeout(r, 50));

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual({
      from: "did:agentmesh:peer-a",
      payload: { text: "recovered" },
    });
  });

  test("async handleFrame rejection is caught, not raised as unhandled rejection", async () => {
    const client = makeClient({ plaintextPeers: ["did:agentmesh:peer-a"] });
    await client.connect();

    const unhandled: unknown[] = [];
    const listener = (err: unknown) => unhandled.push(err);
    process.on("unhandledRejection", listener);

    try {
      // Plaintext message with non-base64 ciphertext — atob throws,
      // handleMessage rejects. Must be caught by the onmessage wrapper.
      lastMockWs!.simulateFrame({
        v: 1,
        type: "message",
        from: "did:agentmesh:peer-a",
        to: "did:agentmesh:test-agent",
        id: "msg-bad-ct",
        ts: new Date().toISOString(),
        ciphertext: "***not-base64***",
        plaintext: true,
      });

      await new Promise((r) => setTimeout(r, 50));

      expect(unhandled).toHaveLength(0);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("handler error"));
    } finally {
      process.off("unhandledRejection", listener);
    }
  });
});
