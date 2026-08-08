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

test("stdio server handles a frame split inside its header", async () => {
  const payload = {
    jsonrpc: "2.0",
    id: 6,
    method: "ping",
    params: { note: "Привет" },
  };
  const frame = Buffer.from(encodeJsonRpcMessage(payload), "utf8");
  const headerEnd = frame.indexOf(Buffer.from("\r\n\r\n", "utf8"));
  assert.notEqual(headerEnd, -1);

  const response = await requestOverStdio(payload, headerEnd + 2);

  assert.deepEqual(response, { jsonrpc: "2.0", id: 6, result: {} });
});

test("stdio server handles a frame split inside a UTF-8 character", async () => {
  const payload = {
    jsonrpc: "2.0",
    id: 7,
    method: "ping",
    params: { note: "Привет" },
  };
  const frame = Buffer.from(encodeJsonRpcMessage(payload), "utf8");
  const characterStart = frame.indexOf(Buffer.from("Привет", "utf8"));
  assert.notEqual(characterStart, -1);

  const response = await requestOverStdio(payload, characterStart + 1);

  assert.deepEqual(response, { jsonrpc: "2.0", id: 7, result: {} });
});

test("stdio server reports malformed LF-only content-length headers", async () => {
  const payload = JSON.stringify({ jsonrpc: "2.0", id: 8, method: "ping" });
  const responses = await requestChunksOverStdio([
    Buffer.from(`Content-Length: ${Buffer.byteLength(payload, "utf8")}\n\n${payload}\n`, "utf8"),
  ]);

  assert.equal(responses[0].error.code, -32700);
  assert.deepEqual(responses[1], { jsonrpc: "2.0", id: 8, result: {} });
});

test("stdio server rejects oversized content-length headers", async () => {
  const [response] = await requestChunksOverStdio([
    Buffer.from("Content-Length: 5242881\r\n\r\n", "utf8"),
  ]);

  assert.equal(response.error.code, -32603);
});

test("stdio server rejects oversized incomplete MCP headers", async () => {
  const [response] = await requestChunksOverStdio([
    Buffer.from(`Content-Length: 1\r\n${"x".repeat(8193)}`, "utf8"),
  ]);

  assert.equal(response.error.code, -32603);
});

test("stdio server rejects oversized complete MCP headers", async () => {
  const [response] = await requestChunksOverStdio([
    Buffer.from(`Content-Length: 1\r\nX-Extension: ${"x".repeat(8193)}\r\n\r\n`, "utf8"),
  ]);

  assert.equal(response.error.code, -32603);
});

test("stdio server rejects oversized unterminated MCP headers", async () => {
  const [response] = await requestChunksOverStdio([Buffer.from("x".repeat(8193), "utf8")]);

  assert.equal(response.error.code, -32603);
});

async function requestOverStdio(payload, splitAt) {
  const frame = Buffer.from(encodeJsonRpcMessage(payload), "utf8");
  const chunks =
    splitAt === undefined ? [frame] : [frame.subarray(0, splitAt), frame.subarray(splitAt)];
  const [response] = await requestChunksOverStdio(chunks);
  return response;
}

async function requestChunksOverStdio(chunks) {
  const child = spawn(process.execPath, [MCP_SERVER_PATH], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));

  const closed = once(child, "close");
  const ready = once(child.stdout, "data");
  child.stdin.write('{"jsonrpc":"2.0","id":"ready","method":"ping"}\n');
  await ready;

  for (const [index, chunk] of chunks.entries()) {
    if (index === chunks.length - 1) {
      child.stdin.end(chunk);
      break;
    }

    child.stdin.write(chunk);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }

  const [code, signal] = await closed;

  assert.equal(code, 0, Buffer.concat(stderr).toString("utf8"));
  assert.equal(signal, null);
  const responses = decodeJsonRpcMessages(Buffer.concat(stdout));
  assert.deepEqual(responses.shift(), { jsonrpc: "2.0", id: "ready", result: {} });
  return responses;
}

function decodeJsonRpcMessages(frame) {
  const separator = Buffer.from("\r\n\r\n", "utf8");
  const messages = [];
  let remaining = frame;

  while (remaining.length > 0) {
    const headerEnd = remaining.indexOf(separator);
    assert.notEqual(headerEnd, -1, "MCP server did not return a framed response");

    const header = remaining.subarray(0, headerEnd).toString("utf8");
    const contentLength = Number(/Content-Length:\s*(\d+)/i.exec(header)?.[1]);
    assert.ok(Number.isSafeInteger(contentLength));

    const bodyStart = headerEnd + separator.length;
    const bodyEnd = bodyStart + contentLength;
    assert.ok(remaining.length >= bodyEnd);
    messages.push(JSON.parse(remaining.subarray(bodyStart, bodyEnd).toString("utf8")));
    remaining = remaining.subarray(bodyEnd);
  }

  return messages;
}
