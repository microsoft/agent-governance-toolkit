// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import test from "node:test";
import assert from "node:assert/strict";

import { encodeJsonRpcMessage, handleJsonRpcRequest } from "../server/agt-mcp.mjs";

import { loadPolicy } from "../lib/policy.mjs";

const state = await loadPolicy();

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
