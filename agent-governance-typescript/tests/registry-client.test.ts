// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Unit tests for RegistryClient and MeshClient auto-register-on-connect.
 *
 * Uses a fake fetch implementation that records requests and serves
 * registry responses, so tests do not require a running registry.
 */

import { RegistryClient, RegistryError } from "../src/encryption/registry-client";
import { MeshClient } from "../src/encryption/mesh-client";
import { X3DHKeyManager } from "../src/encryption/x3dh";
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "node:crypto";

// ── Fake fetch ─────────────────────────────────────────────────

interface RecordedRequest {
  method: string;
  url: string;
  body?: string;
  headers: Record<string, string>;
}

function makeFakeFetch(responder: (req: RecordedRequest) => { status: number; body: string }) {
  const calls: RecordedRequest[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = init.headers as Record<string, string>;
      for (const k of Object.keys(h)) headers[k.toLowerCase()] = h[k];
    }
    const rec: RecordedRequest = {
      method: init?.method ?? "GET",
      url: u,
      body: typeof init?.body === "string" ? init.body : undefined,
      headers,
    };
    calls.push(rec);
    const r = responder(rec);
    return new Response(r.body, { status: r.status, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

function makeKeyManager() {
  const sk = new Uint8Array(randomBytes(32));
  const pk = ed25519.getPublicKey(sk);
  return new X3DHKeyManager(sk, pk);
}

// ── RegistryClient ─────────────────────────────────────────────

describe("RegistryClient", () => {
  it("register encodes public_key as base64url and posts to /v1/agents", async () => {
    const { fetchImpl, calls } = makeFakeFetch(() => ({ status: 201, body: "{}" }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl });
    const key = new Uint8Array(32).fill(7);
    await c.register("did:agent:alice", key, ["echo"], { display_name: "Alice" });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe("http://reg:8082/v1/agents");
    const body = JSON.parse(calls[0].body!);
    expect(body.did).toBe("did:agent:alice");
    expect(body.public_key).toBe(Buffer.from(key).toString("base64url"));
    expect(body.capabilities).toEqual(["echo"]);
    expect(body.metadata).toEqual({ display_name: "Alice" });
  });

  it("register treats 409 as success (idempotent)", async () => {
    const { fetchImpl } = makeFakeFetch(() => ({ status: 409, body: '{"detail":"already"}' }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl, maxRetries: 0 });
    await expect(c.register("did:x", new Uint8Array(32))).resolves.toBeUndefined();
  });

  it("register throws RegistryError on 4xx other than 409", async () => {
    const { fetchImpl } = makeFakeFetch(() => ({ status: 400, body: '{"detail":"bad"}' }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl, maxRetries: 0 });
    await expect(c.register("did:x", new Uint8Array(32))).rejects.toBeInstanceOf(RegistryError);
  });

  it("uploadPrekeys serialises signed_pre_key + one_time_pre_keys", async () => {
    const { fetchImpl, calls } = makeFakeFetch(() => ({ status: 200, body: '{"otk_count":2}' }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl });
    const idk = new Uint8Array(32).fill(1);
    const idkEd = new Uint8Array(32).fill(9);
    await c.uploadPrekeys(
      "did:agent:bob",
      idk,
      idkEd,
      { keyId: 0, publicKey: new Uint8Array(32).fill(2), signature: new Uint8Array(64).fill(3) },
      [
        { keyId: 0, publicKey: new Uint8Array(32).fill(4) },
        { keyId: 1, publicKey: new Uint8Array(32).fill(5) },
      ],
    );
    expect(calls[0].method).toBe("PUT");
    expect(calls[0].url).toBe("http://reg:8082/v1/agents/did%3Aagent%3Abob/prekeys");
    const body = JSON.parse(calls[0].body!);
    expect(body.identity_key).toBe(Buffer.from(idk).toString("base64url"));
    expect(body.identity_key_ed).toBe(Buffer.from(idkEd).toString("base64url"));
    expect(body.signed_pre_key.key_id).toBe(0);
    expect(body.one_time_pre_keys).toHaveLength(2);
  });

  it("fetchPrekeys decodes base64url back to Uint8Array", async () => {
    const idk = new Uint8Array(32).fill(9);
    const idkEd = new Uint8Array(32).fill(11);
    const spk = new Uint8Array(32).fill(8);
    const sig = new Uint8Array(64).fill(7);
    const otk = new Uint8Array(32).fill(6);
    const body = JSON.stringify({
      identity_key: Buffer.from(idk).toString("base64url"),
      identity_key_ed: Buffer.from(idkEd).toString("base64url"),
      signed_pre_key: {
        key_id: 0,
        public_key: Buffer.from(spk).toString("base64url"),
        signature: Buffer.from(sig).toString("base64url"),
      },
      one_time_pre_key: {
        key_id: 7,
        public_key: Buffer.from(otk).toString("base64url"),
      },
    });
    const { fetchImpl } = makeFakeFetch(() => ({ status: 200, body }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl });
    const bundle = await c.fetchPrekeys("did:peer");
    expect(bundle).not.toBeNull();
    expect(Array.from(bundle!.identityKey)).toEqual(Array.from(idk));
    expect(Array.from(bundle!.identityKeyEd)).toEqual(Array.from(idkEd));
    expect(Array.from(bundle!.signedPreKey)).toEqual(Array.from(spk));
    expect(Array.from(bundle!.signedPreKeySignature)).toEqual(Array.from(sig));
    expect(bundle!.signedPreKeyId).toBe(0);
    expect(Array.from(bundle!.oneTimePreKey!)).toEqual(Array.from(otk));
    expect(bundle!.oneTimePreKeyId).toBe(7);
  });

  it("fetchPrekeys returns null on 404", async () => {
    const { fetchImpl } = makeFakeFetch(() => ({ status: 404, body: "{}" }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl });
    expect(await c.fetchPrekeys("did:missing")).toBeNull();
  });

  it("discover parses {results,total} envelope", async () => {
    const body = JSON.stringify({
      results: [
        { did: "did:a", capabilities: ["echo"], reputation_score: 0.9, last_seen: "2026-01-01T00:00:00Z" },
        { did: "did:b", capabilities: ["echo", "search"], reputation_score: 0.5, last_seen: "2026-01-01T00:01:00Z" },
      ],
      total: 2,
    });
    const { fetchImpl, calls } = makeFakeFetch(() => ({ status: 200, body }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl });
    const results = await c.discover("echo", 10);
    expect(calls[0].url).toBe("http://reg:8082/v1/discover?capability=echo&limit=10");
    expect(results).toHaveLength(2);
    expect(results[0].did).toBe("did:a");
    expect(results[0].reputationScore).toBe(0.9);
    expect(results[0].lastSeen).toBeInstanceOf(Date);
  });

  it("retries on 5xx then succeeds", async () => {
    let n = 0;
    const { fetchImpl } = makeFakeFetch(() => {
      n++;
      return n < 2 ? { status: 503, body: "{}" } : { status: 200, body: '{"results":[],"total":0}' };
    });
    const c = new RegistryClient({
      baseUrl: "http://reg:8082",
      fetchImpl,
      maxRetries: 2,
      retryBaseDelayMs: 1,
    });
    const r = await c.discover("anything");
    expect(r).toEqual([]);
    expect(n).toBe(2);
  });

  it("attaches Ed25519-Timestamp Authorization header when authSigner is set", async () => {
    const { fetchImpl, calls } = makeFakeFetch(() => ({ status: 200, body: '{"results":[],"total":0}' }));
    const sig = new Uint8Array(64).fill(0xab);
    const c = new RegistryClient({
      baseUrl: "http://reg:8082",
      fetchImpl,
      authSigner: { did: "did:agent:caller", sign: () => sig },
    });
    await c.discover("x");
    const auth = calls[0].headers["authorization"];
    expect(auth).toMatch(/^Ed25519-Timestamp did:agent:caller \S+ \S+$/);
  });
});

// ── MeshClient.connect auto-register ───────────────────────────

describe("MeshClient auto-register on connect", () => {
  it("posts /v1/agents and PUTs /v1/agents/{did}/prekeys after WS open", async () => {
    const { fetchImpl, calls } = makeFakeFetch((req) => {
      if (req.method === "POST") return { status: 201, body: "{}" };
      if (req.method === "PUT") return { status: 200, body: '{"otk_count":3}' };
      return { status: 404, body: "{}" };
    });

    // Fake WS that resolves immediately on construction.
    class FakeWs {
      readyState = 1;
      onopen: ((e: unknown) => void) | null = null;
      onmessage: ((e: unknown) => void) | null = null;
      onerror: ((e: unknown) => void) | null = null;
      onclose: ((e: unknown) => void) | null = null;
      sent: string[] = [];
      constructor() {
        // Defer to next microtask so handlers are wired.
        queueMicrotask(() => this.onopen?.({}));
      }
      send(d: string) {
        this.sent.push(d);
      }
      close() {
        this.onclose?.({ code: 1000 });
      }
    }

    const km = makeKeyManager();
    const client = new MeshClient({
      relayUrl: "http://relay:8083",
      registryUrl: "http://reg:8082",
      keyManager: km,
      agentDid: "did:agent:alice",
      displayName: "Alice",
      capabilities: ["echo"],
      oneTimePrekeyCount: 3,
      autoReconnect: false,
      wsFactory: () => new FakeWs() as unknown as WebSocket,
      registryClientOptions: { fetchImpl, maxRetries: 0 },
    });

    await client.connect();
    await client.disconnect();

    // Expect 1 POST and 1 PUT to the registry.
    const posts = calls.filter((c) => c.method === "POST");
    const puts = calls.filter((c) => c.method === "PUT");
    expect(posts).toHaveLength(1);
    expect(puts).toHaveLength(1);

    const reg = JSON.parse(posts[0].body!);
    expect(reg.did).toBe("did:agent:alice");
    // displayName is auto-included in capabilities so peers can find Alice
    // via discover("Alice").
    expect(reg.capabilities).toEqual(["Alice", "echo"]);
    expect(reg.metadata.display_name).toBe("Alice");

    const pk = JSON.parse(puts[0].body!);
    expect(pk.signed_pre_key).toBeDefined();
    expect(pk.one_time_pre_keys).toHaveLength(3);
  });

  it("autoRegister:false skips registry calls", async () => {
    const { fetchImpl, calls } = makeFakeFetch(() => ({ status: 500, body: "should not be called" }));

    class FakeWs {
      readyState = 1;
      onopen: ((e: unknown) => void) | null = null;
      onmessage: ((e: unknown) => void) | null = null;
      onerror: ((e: unknown) => void) | null = null;
      onclose: ((e: unknown) => void) | null = null;
      constructor() { queueMicrotask(() => this.onopen?.({})); }
      send() {}
      close() { this.onclose?.({ code: 1000 }); }
    }

    const client = new MeshClient({
      relayUrl: "http://relay:8083",
      registryUrl: "http://reg:8082",
      keyManager: makeKeyManager(),
      agentDid: "did:agent:bob",
      autoReconnect: false,
      autoRegister: false,
      wsFactory: () => new FakeWs() as unknown as WebSocket,
      registryClientOptions: { fetchImpl, maxRetries: 0 },
    });

    await client.connect();
    await client.disconnect();
    expect(calls).toHaveLength(0);
  });
});

describe("RegistryClient fetchPrekeys identity_key_ed validation", () => {
  it("throws when peer bundle is missing identity_key_ed", async () => {
    const bundle = {
      identity_key: toBase64UrlHelper(new Uint8Array(32).fill(1)),
      signed_pre_key: {
        key_id: 1,
        public_key: toBase64UrlHelper(new Uint8Array(32).fill(2)),
        signature: toBase64UrlHelper(new Uint8Array(64).fill(3)),
      },
      one_time_pre_key: null,
    };
    const { fetchImpl } = makeFakeFetch(() => ({
      status: 200,
      body: JSON.stringify(bundle),
    }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl, maxRetries: 0 });

    await expect(c.fetchPrekeys("did:old-peer")).rejects.toThrow(
      /identity_key_ed/,
    );
  });

  it("succeeds when identity_key_ed is present", async () => {
    const bundle = {
      identity_key: toBase64UrlHelper(new Uint8Array(32).fill(1)),
      identity_key_ed: toBase64UrlHelper(new Uint8Array(32).fill(7)),
      signed_pre_key: {
        key_id: 1,
        public_key: toBase64UrlHelper(new Uint8Array(32).fill(2)),
        signature: toBase64UrlHelper(new Uint8Array(64).fill(3)),
      },
      one_time_pre_key: null,
    };
    const { fetchImpl } = makeFakeFetch(() => ({
      status: 200,
      body: JSON.stringify(bundle),
    }));
    const c = new RegistryClient({ baseUrl: "http://reg:8082", fetchImpl, maxRetries: 0 });

    const result = await c.fetchPrekeys("did:new-peer");
    expect(result).not.toBeNull();
    expect(result!.identityKeyEd[0]).toBe(7);
  });
});

function toBase64UrlHelper(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
