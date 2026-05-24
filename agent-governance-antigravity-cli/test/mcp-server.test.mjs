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
