// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentMesh API Integration Tests
 *
 * Run with: npx ts-node tests/api.test.ts
 * Uses Node.js built-in assert — no external test dependencies required.
 */
import * as assert from "assert";
import * as http from "http";
import express from "express";
import { rateLimit, resetRateLimitStore } from "../src/middleware/rateLimit";
import { requireApiKey } from "../src/middleware/apiKey";
import healthRouter from "../src/routes/health";
import registerRouter from "../src/routes/register";
import verifyRouter from "../src/routes/verify";
import handshakeRouter from "../src/routes/handshake";
import scoreRouter from "../src/routes/score";
import { resetRegistry } from "../src/services/registry";
import { resetAuditLog } from "../src/services/audit";

// ---------- helpers ----------

function createApp(): express.Express {
  const app = express();
  app.use(express.json());
  app.use(rateLimit);

  app.use("/api", healthRouter);
  app.use("/api", verifyRouter);
  app.use("/api", scoreRouter);
  app.use("/api", requireApiKey, registerRouter);
  app.use("/api", requireApiKey, handshakeRouter);

  return app;
}

function request(
  server: http.Server,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const addr = server.address() as { port: number };
    const data = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: addr.port,
        path,
        method,
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode!, body: JSON.parse(raw) });
          } catch {
            resolve({ status: res.statusCode!, body: raw });
          }
        });
      },
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

// ---------- test runner ----------

const tests: { name: string; fn: (server: http.Server) => Promise<void> }[] = [];

function test(name: string, fn: (server: http.Server) => Promise<void>) {
  tests.push({ name, fn });
}

// ---------- tests ----------

test("GET /api/health returns ok", async (server) => {
  const res = await request(server, "GET", "/api/health");
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, "ok");
  assert.strictEqual(res.body.service, "agentmesh-api");
  assert.ok(res.body.timestamp);
});

test("POST /api/register requires API key", async (server) => {
  const res = await request(server, "POST", "/api/register", {
    name: "TestAgent",
    sponsor_email: "test@example.com",
    capabilities: ["read"],
  });
  assert.strictEqual(res.status, 401);
});

test("POST /api/register validates input", async (server) => {
  // First register an agent to get an API key for subsequent calls
  // For the first registration, we need a bootstrap mechanism.
  // The API requires an API key to register, so we test validation
  // by providing an invalid key.
  const res = await request(
    server,
    "POST",
    "/api/register",
    { capabilities: ["read"] },
    { "x-api-key": "amesh_bootstrap" },
  );
  // Invalid key → 403
  assert.strictEqual(res.status, 403);
});

test("Full registration and verification flow", async (server) => {
  // We need a bootstrap key. Let's register directly via registry service
  // then use the resulting API key.
  const { registerAgent } = await import("../src/services/registry");
  const agent = registerAgent({
    name: "FlowTest",
    sponsor_email: "flow@example.com",
    capabilities: ["read", "write", "execute"],
  });

  // Now verify the agent
  const verifyRes = await request(server, "GET", `/api/verify/${agent.did}`);
  assert.strictEqual(verifyRes.status, 200);
  assert.strictEqual(verifyRes.body.registered, true);
  assert.ok(verifyRes.body.trust_score > 0);
  assert.strictEqual(verifyRes.body.sponsor, "flow@example.com");
  assert.strictEqual(verifyRes.body.status, "active");
  assert.deepStrictEqual(verifyRes.body.capabilities, [
    "read",
    "write",
    "execute",
  ]);

  // Now register via API using the agent's API key
  const regRes = await request(
    server,
    "POST",
    "/api/register",
    {
      name: "SecondAgent",
      sponsor_email: "second@example.com",
      capabilities: ["read"],
    },
    { "x-api-key": agent.api_key },
  );
  assert.strictEqual(regRes.status, 201);
  assert.ok(regRes.body.agent_did.startsWith("did:mesh:"));
  assert.ok(regRes.body.api_key.startsWith("amesh_"));
  assert.ok(regRes.body.public_key);
  assert.ok(regRes.body.verification_url);
});

test("GET /api/verify/:agentDid returns 404 for unknown agent", async (server) => {
  const res = await request(server, "GET", "/api/verify/did:mesh:unknown");
  assert.strictEqual(res.status, 404);
  assert.strictEqual(res.body.registered, false);
});

test("POST /api/handshake succeeds for registered agent", async (server) => {
  const { registerAgent } = await import("../src/services/registry");
  const agent = registerAgent({
    name: "HandshakeAgent",
    sponsor_email: "hs@example.com",
    capabilities: ["read", "write"],
  });

  const res = await request(
    server,
    "POST",
    "/api/handshake",
    {
      agent_did: agent.did,
      challenge: "test-challenge-nonce-123",
      capabilities_requested: ["read", "admin"],
    },
    { "x-api-key": agent.api_key },
  );

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.verified, true);
  assert.ok(res.body.trust_score > 0);
  // Should grant 'read' but not 'admin' (agent doesn't have it)
  assert.ok(res.body.capabilities_granted.includes("read"));
  assert.ok(!res.body.capabilities_granted.includes("admin"));
  assert.ok(res.body.signature);
});

test("POST /api/handshake returns 404 for unknown agent", async (server) => {
  const { registerAgent } = await import("../src/services/registry");
  const agent = registerAgent({
    name: "KeyHolder",
    sponsor_email: "kh@example.com",
    capabilities: [],
  });

  const res = await request(
    server,
    "POST",
    "/api/handshake",
    {
      agent_did: "did:mesh:nonexistent",
      challenge: "test",
      capabilities_requested: [],
    },
    { "x-api-key": agent.api_key },
  );
  assert.strictEqual(res.status, 404);
});

test("GET /api/score/:agentDid returns trust breakdown", async (server) => {
  const { registerAgent } = await import("../src/services/registry");
  const agent = registerAgent({
    name: "ScoreAgent",
    sponsor_email: "score@example.com",
    capabilities: ["read"],
  });

  const res = await request(server, "GET", `/api/score/${agent.did}`);
  assert.strictEqual(res.status, 200);
  assert.ok(typeof res.body.total === "number");
  assert.ok(res.body.dimensions);
  assert.ok(typeof res.body.dimensions.policy_compliance === "number");
  assert.ok(typeof res.body.dimensions.interaction_success === "number");
  assert.ok(typeof res.body.dimensions.verification_depth === "number");
  assert.ok(typeof res.body.dimensions.community_vouching === "number");
  assert.ok(typeof res.body.dimensions.uptime_reliability === "number");
  assert.ok(res.body.tier);
  assert.ok(Array.isArray(res.body.history));
  assert.ok(res.body.history.length > 0);
});

test("GET /api/score/:agentDid returns 404 for unknown agent", async (server) => {
  const res = await request(server, "GET", "/api/score/did:mesh:nope");
  assert.strictEqual(res.status, 404);
});

// ---------- run ----------

async function run() {
  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    // Reset state before each test
    resetRegistry();
    resetAuditLog();
    resetRateLimitStore();

    const app = createApp();
    const server = app.listen(0);

    try {
      await t.fn(server);
      console.log(`  ✓ ${t.name}`);
      passed++;
    } catch (err: any) {
      console.error(`  ✗ ${t.name}`);
      console.error(`    ${err.message}`);
      failed++;
    } finally {
      server.close();
    }
  }

  console.log(`\n${passed} passed, ${failed} failed, ${tests.length} total`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
