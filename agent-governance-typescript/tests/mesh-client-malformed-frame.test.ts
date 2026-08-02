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

  // handlePendingMessages drains a relay-supplied batch. A single poisoned
  // entry must not abort the drain and silently discard the rest of the
  // mailbox — otherwise one malformed queued message (or a malicious relay
  // deliberately placing one first) suppresses every message behind it.
  test("one malformed pending message does not discard the rest of the batch", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: unknown[] = [];
    const errors: Array<{ kind: string; detail: string }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));
    client.onError((kind, _from, detail) => errors.push({ kind, detail }));

    await client.connect();

    const msg = (id: string, ciphertext: string) => ({
      v: 1,
      type: "message",
      from: peer,
      to: "did:agentmesh:test-agent",
      id,
      ts: new Date().toISOString(),
      ciphertext,
      plaintext: true,
    });

    lastMockWs!.simulateFrame({
      v: 1,
      type: "pending_messages",
      messages: [
        // Poisoned first entry: atob() throws inside handleMessage.
        msg("pending-bad", "***not-base64***"),
        msg("pending-good-1", btoa(JSON.stringify({ text: "one" }))),
        msg("pending-good-2", btoa(JSON.stringify({ text: "two" }))),
      ],
    });

    await new Promise((r) => setTimeout(r, 80));

    // Both well-formed messages behind the poisoned one are still delivered.
    expect(received).toEqual([
      { from: peer, payload: { text: "one" } },
      { from: peer, payload: { text: "two" } },
    ]);
    // And the failure is surfaced rather than swallowed silently.
    expect(errors.some((e) => e.kind === "frame" && /pending message dropped/.test(e.detail))).toBe(
      true,
    );
  });

  // Regression guard for the isolation above: the per-message catch block must
  // itself be total. `messages` is relay-supplied JSON, so an entry can be
  // `null`. handleMessage() dereferences `frame.from` and throws on it, and if
  // the catch block then also dereferences `msg.from` it throws a second time —
  // from inside the catch, where nothing can catch it. That escapes the loop and
  // discards every message behind the null entry, which is precisely the
  // failure mode the try/catch exists to prevent. A hostile relay could use a
  // single leading `null` to silently suppress a victim's entire mailbox.
  test("a null pending entry does not abort the drain or suppress messages behind it", async () => {
    const peer = "did:agentmesh:peer-a";
    const client = makeClient({ plaintextPeers: [peer] });
    const received: unknown[] = [];
    const errors: Array<{ kind: string; detail: string }> = [];
    client.onMessage((from, payload) => received.push({ from, payload }));
    client.onError((kind, _from, detail) => errors.push({ kind, detail }));

    await client.connect();

    const msg = (id: string, ciphertext: string) => ({
      v: 1,
      type: "message",
      from: peer,
      to: "did:agentmesh:test-agent",
      id,
      ts: new Date().toISOString(),
      ciphertext,
      plaintext: true,
    });

    const unhandled: unknown[] = [];
    const listener = (err: unknown) => unhandled.push(err);
    process.on("unhandledRejection", listener);

    try {
      lastMockWs!.simulateFrame({
        v: 1,
        type: "pending_messages",
        messages: [
          // Non-object entries a relay can legally emit in JSON. `null` is the
          // dangerous one: property access on it throws.
          null,
          "not-an-object",
          42,
          msg("pending-good-1", btoa(JSON.stringify({ text: "one" }))),
          msg("pending-good-2", btoa(JSON.stringify({ text: "two" }))),
        ],
      });

      await new Promise((r) => setTimeout(r, 80));

      // The well-formed messages behind the null entry are still delivered.
      expect(received).toEqual([
        { from: peer, payload: { text: "one" } },
        { from: peer, payload: { text: "two" } },
      ]);
      // The dropped entries are reported, not silently skipped.
      expect(
        errors.filter((e) => e.kind === "frame" && /pending message dropped/.test(e.detail)).length,
      ).toBe(3);
      // And nothing escaped as an unhandled rejection.
      expect(unhandled).toHaveLength(0);
    } finally {
      process.off("unhandledRejection", listener);
    }
  });
});
