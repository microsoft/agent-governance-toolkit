// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

import { encodeJsonRpcMessage, handleJsonRpcRequest } from "../server/agt-mcp.mjs";

import { loadPolicy } from "../lib/policy.mjs";

const state = await loadPolicy();
const MCP_SERVER_PATH = fileURLToPath(new URL("../server/agt-mcp.mjs", import.meta.url));

test("initialize returns MCP server metadata", async () => {
  const response = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
    },
  });

  assert.equal(response.result.protocolVersion, "2024-11-05");
  assert.deepEqual(response.result.capabilities, { tools: {} });
  assert.equal(response.result.serverInfo.name, "agt-governance");
});

test("tools/list returns the governance tools", async () => {
  const response = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });

  const toolNames = response.result.tools.map((tool) => tool.name);
  assert.deepEqual(toolNames, ["agt_policy_status", "agt_policy_check_text"]);
});

test("tools/call rejects invalid agt_policy_check_text arguments", async () => {
  const response = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "agt_policy_check_text",
      arguments: {},
    },
  });

  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /requires a string 'text' argument/i);
});

test("encoded JSON-RPC messages include a content-length header", () => {
  const encoded = encodeJsonRpcMessage({
    jsonrpc: "2.0",
    id: 4,
    result: {
      ok: true,
    },
  });

  assert.match(encoded, /^Content-Length: \d+\r\n\r\n/);
  assert.match(encoded, /"ok":true/);
});

test("stdio server handles UTF-8 JSON-RPC frames", async () => {
  const response = await requestOverStdio({
    jsonrpc: "2.0",
    id: 5,
    method: "ping",
    params: { note: "Привет" },
  });

  assert.deepEqual(response, { jsonrpc: "2.0", id: 5, result: {} });
});

async function requestOverStdio(payload) {
  const child = spawn(process.execPath, [MCP_SERVER_PATH], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));

  const closed = once(child, "close");
  child.stdin.end(encodeJsonRpcMessage(payload));
  const [code, signal] = await closed;

  assert.equal(code, 0, Buffer.concat(stderr).toString("utf8"));
  assert.equal(signal, null);
  return decodeJsonRpcMessage(Buffer.concat(stdout));
}

function decodeJsonRpcMessage(frame) {
  const separator = Buffer.from("\r\n\r\n", "utf8");
  const headerEnd = frame.indexOf(separator);
  assert.notEqual(headerEnd, -1, "MCP server did not return a framed response");

  const header = frame.subarray(0, headerEnd).toString("utf8");
  const contentLength = Number(/Content-Length:\s*(\d+)/i.exec(header)?.[1]);
  assert.ok(Number.isSafeInteger(contentLength));

  const bodyStart = headerEnd + separator.length;
  const bodyEnd = bodyStart + contentLength;
  assert.equal(frame.length, bodyEnd);
  return JSON.parse(frame.subarray(bodyStart, bodyEnd).toString("utf8"));
}
