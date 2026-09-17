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
    child.stdin.write(encodeMessage(payload));
  });
}

function encodeMessage(payload) {
  const body = JSON.stringify(payload);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

function tryDecodeMessage(buffer) {
  const separator = "\r\n\r\n";
  const headerEnd = buffer.indexOf(separator);
  if (headerEnd === -1) {
    return null;
  }

  const headerText = buffer.subarray(0, headerEnd).toString("utf8");
  const contentLengthHeader = headerText
    .split("\r\n")
    .find((line) => line.toLowerCase().startsWith("content-length:"));
  if (!contentLengthHeader) {
    throw new Error("MCP response is missing Content-Length.");
  }

  const contentLength = Number.parseInt(contentLengthHeader.split(":")[1].trim(), 10);
  const messageStart = headerEnd + separator.length;
  const messageEnd = messageStart + contentLength;
  if (buffer.length < messageEnd) {
    return null;
  }

  return JSON.parse(buffer.subarray(messageStart, messageEnd).toString("utf8"));
}
