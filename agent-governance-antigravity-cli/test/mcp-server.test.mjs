// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installPackage } from "../lib/cli.mjs";

const PACKAGE_ROOT = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const STATELESS_META = {
  clientInfo: {
    name: "agt-parity-test",
    version: "1.0.0",
  },
  capabilities: {},
};

test("bundled MCP server handles initialize, tools/list, and tools/call over stdio", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-mcp-server-"));
  const antigravityHome = join(root, ".antigravity");

  await installPackage({ antigravityHome, packageRoot: PACKAGE_ROOT });
  const serverPath = join(antigravityHome, "extensions", "agt-global-policy", "mcp", "server.mjs");
  const child = spawn(process.execPath, [serverPath], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  try {
    const initialize = await request(child, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "agt-test",
          version: "1.0.0",
        },
      },
    });
    assert.equal(initialize.result.protocolVersion, "2024-11-05");
    assert.equal(initialize.result.serverInfo.name, "agt-global-policy");

    child.stdin.write(encodeMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }));

    const listTools = await request(child, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    assert.deepEqual(
      listTools.result.tools.map(({ name }) => name),
      ["agt_policy_status", "agt_policy_check_text"],
    );

    const policyStatus = await request(child, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
    });
    const parsedStatus = JSON.parse(policyStatus.result.content[0].text);
    assert.equal(typeof parsedStatus.summary, "string");
    assert.equal(typeof parsedStatus.status.mode, "string");

    const missingText = await request(child, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "agt_policy_check_text",
        arguments: {},
      },
    });
    assert.equal(missingText.result.isError, true);
    assert.match(missingText.result.content[0].text, /text.*required/i);
  } finally {
    child.kill();
    await rm(root, { recursive: true, force: true });
  }
});

test("server/discover matches legacy capability and tool declarations over stdio", async () => {
  await withServer("agt-antigravity-mcp-discover-", async (child) => {
    const initialize = await request(child, {
      jsonrpc: "2.0",
      id: 10,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    });
    const listTools = await request(child, {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/list",
      params: {},
    });
    const discover = await request(child, {
      jsonrpc: "2.0",
      id: 12,
      method: "server/discover",
      params: {},
      _meta: STATELESS_META,
    });

    assert.equal(initialize.result.protocolVersion, "2024-11-05");
    assert.equal(discover.result.protocolVersion, "2026-07-28");
    assert.deepEqual(discover.result.capabilities, initialize.result.capabilities);
    assert.deepEqual(discover.result.serverInfo, initialize.result.serverInfo);
    assert.deepEqual(discover.result.tools, listTools.result.tools);
    assert.equal("sessionId" in discover.result, false);
  });
});

test("stateless tools/list validates per-request _meta over stdio", async () => {
  await withServer("agt-antigravity-mcp-meta-list-", async (child) => {
    const accepted = await request(child, {
      jsonrpc: "2.0",
      id: 13,
      method: "tools/list",
      params: {},
      _meta: STATELESS_META,
    });
    const rejected = await request(child, {
      jsonrpc: "2.0",
      id: 14,
      method: "tools/list",
      params: {},
      _meta: { capabilities: {} },
    });

    assert.deepEqual(accepted.result.tools.map(({ name }) => name), [
      "agt_policy_status",
      "agt_policy_check_text",
    ]);
    assert.equal(rejected.error.code, -32001);
  });
});

test("stateless tools/call rejects missing caller identity after discovery over stdio", async () => {
  await withServer("agt-antigravity-mcp-meta-deny-", async (child) => {
    const discover = await request(child, {
      jsonrpc: "2.0",
      id: 15,
      method: "server/discover",
      params: {},
      _meta: STATELESS_META,
    });
    const rejected = await request(child, {
      jsonrpc: "2.0",
      id: 16,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
      _meta: { capabilities: {} },
    });

    assert.equal(discover.result.protocolVersion, "2026-07-28");
    assert.equal(rejected.error.code, -32001);
    assert.equal("result" in rejected, false);
  });
});

test("stateless tools/call preserves caller context over stdio", async () => {
  await withServer("agt-antigravity-mcp-meta-call-", async (child) => {
    const response = await request(child, {
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
      _meta: STATELESS_META,
    });

    assert.deepEqual(response.result._meta, STATELESS_META);
    assert.equal(response.result.isError, undefined);
  });
});

test("legacy lifecycle remains compatible and terminal outcomes stay distinct over stdio", async () => {
  await withServer("agt-antigravity-mcp-compat-", async (child) => {
    const initialize = await request(child, {
      jsonrpc: "2.0",
      id: 18,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    });
    child.stdin.write(encodeMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }));
    const compatibilityFallback = await request(child, {
      jsonrpc: "2.0",
      id: 19,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
    });
    const allow = await request(child, {
      jsonrpc: "2.0",
      id: 20,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
      _meta: STATELESS_META,
    });
    const deny = await request(child, {
      jsonrpc: "2.0",
      id: 21,
      method: "tools/call",
      params: {
        name: "agt_policy_status",
        arguments: {},
      },
      _meta: { capabilities: {} },
    });

    assert.equal(initialize.result.protocolVersion, "2024-11-05");
    assert.equal(compatibilityFallback.result.isError, undefined);
    assert.notDeepEqual(allow.result, deny.error ?? deny.result);
    assert.notDeepEqual(allow.result, compatibilityFallback.result);
    assert.notDeepEqual(deny.error ?? deny.result, compatibilityFallback.result);
  });
});

test("bundled MCP server completes a newline-delimited JSON handshake over stdio", async () => {
  await withServer("agt-antigravity-mcp-ndjson-handshake-", async (child) => {
    const initialize = await request(child, {
      jsonrpc: "2.0",
      id: 30,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    });
    child.stdin.write(encodeMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }));
    const listTools = await request(child, {
      jsonrpc: "2.0",
      id: 31,
      method: "tools/list",
      params: {},
      _meta: STATELESS_META,
    });
    const discover = await request(child, {
      jsonrpc: "2.0",
      id: 32,
      method: "server/discover",
      params: {},
      _meta: STATELESS_META,
    });

    assert.equal(initialize.result.serverInfo.name, "agt-global-policy");
    assert.deepEqual(listTools.result.tools.map(({ name }) => name), [
      "agt_policy_status",
      "agt_policy_check_text",
    ]);
    assert.equal(discover.result.protocolVersion, "2026-07-28");
  });
});

test("bundled MCP server frames responses as newline-delimited JSON", async () => {
  await withServer("agt-antigravity-mcp-ndjson-frame-", async (child) => {
    const raw = await rawResponse(child, { jsonrpc: "2.0", id: 33, method: "ping", params: {} });

    assert.ok(raw.endsWith("\n"));
    assert.equal(raw.indexOf("\n"), raw.length - 1);
    assert.deepEqual(JSON.parse(raw), { jsonrpc: "2.0", id: 33, result: {} });
  });
});

test("bundled MCP server handles a newline-delimited frame split across writes", async () => {
  await withServer("agt-antigravity-mcp-ndjson-split-", async (child) => {
    const frame = Buffer.from(
      encodeMessage({ jsonrpc: "2.0", id: 34, method: "ping", params: { note: "Привет" } }),
      "utf8",
    );
    const characterStart = frame.indexOf(Buffer.from("Привет", "utf8"));
    assert.notEqual(characterStart, -1);

    const response = await requestFrame(child, [
      frame.subarray(0, characterStart + 1),
      frame.subarray(characterStart + 1),
    ]);

    assert.deepEqual(response, { jsonrpc: "2.0", id: 34, result: {} });
  });
});

test("bundled MCP server still reads legacy Content-Length requests", async () => {
  await withServer("agt-antigravity-mcp-legacy-read-", async (child) => {
    const response = await requestFrame(
      child,
      encodeLegacyContentLengthFrame({ jsonrpc: "2.0", id: 35, method: "ping", params: {} }),
    );

    assert.deepEqual(response, { jsonrpc: "2.0", id: 35, result: {} });
  });
});

test("bundled MCP server rejects a legacy frame without Content-Length", async () => {
  await withServer("agt-antigravity-mcp-legacy-bad-header-", async (child) => {
    const response = await requestFrame(
      child,
      'X-Extension: 1\r\n\r\n{"jsonrpc":"2.0","id":36,"method":"ping"}',
    );

    assert.equal(response.error.code, -32700);
    assert.equal(response.error.message, "Missing or invalid Content-Length header.");
  });
});

test("bundled MCP server rejects a malformed newline-delimited line", async () => {
  await withServer("agt-antigravity-mcp-bad-json-", async (child) => {
    const response = await requestFrame(child, "{not json}\n");

    assert.equal(response.error.code, -32700);
    assert.equal(response.error.message, "Invalid JSON payload.");
  });
});

async function withServer(prefix, callback) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const antigravityHome = join(root, ".antigravity");

  await installPackage({ antigravityHome, packageRoot: PACKAGE_ROOT });
  const serverPath = join(antigravityHome, "extensions", "agt-global-policy", "mcp", "server.mjs");
  const child = spawn(process.execPath, [serverPath], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  try {
    await callback(child);
  } finally {
    child.kill();
    await rm(root, { recursive: true, force: true });
  }
}

function request(child, payload) {
  return requestFrame(child, encodeMessage(payload));
}

function requestFrame(child, frame) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;

    const cleanup = () => {
      child.stdout.off("data", onData);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onError = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };
    const onExit = (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(new Error(`MCP server exited before responding (code=${code}, signal=${signal ?? "none"}).`));
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const response = tryDecodeMessage(buffer);
      if (!response) {
        return;
      }
      settled = true;
      cleanup();
      resolve(response);
    };

    child.stdout.on("data", onData);
    child.on("error", onError);
    child.on("exit", onExit);
    void writeChunks(child, Array.isArray(frame) ? frame : [frame]);
  });
}

async function writeChunks(child, chunks) {
  for (const [index, chunk] of chunks.entries()) {
    child.stdin.write(chunk);
    if (index < chunks.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
}

function encodeMessage(payload) {
  return `${JSON.stringify(payload)}\n`;
}

// The read side still accepts legacy LSP frames, so the legacy tests drive the
// server with Content-Length input while it answers with NDJSON.
function encodeLegacyContentLengthFrame(payload) {
  const body = JSON.stringify(payload);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

function tryDecodeMessage(buffer) {
  const newlineIndex = buffer.indexOf(0x0a);
  if (newlineIndex === -1) {
    return null;
  }

  const line = buffer.subarray(0, newlineIndex).toString("utf8");
  assert.doesNotMatch(line, /^Content-Length:/i, "MCP server framed a response with an LSP header");

  return JSON.parse(line);
}

function rawResponse(child, payload) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);

    const cleanup = () => {
      child.stdout.off("data", onData);
      child.off("error", onError);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const newlineIndex = buffer.indexOf(0x0a);
      if (newlineIndex === -1) {
        return;
      }
      cleanup();
      resolve(buffer.subarray(0, newlineIndex + 1).toString("utf8"));
    };

    child.stdout.on("data", onData);
    child.on("error", onError);
    child.stdin.write(encodeMessage(payload));
  });
}
