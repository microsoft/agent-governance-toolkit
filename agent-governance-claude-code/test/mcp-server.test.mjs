// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import test from "node:test";
import assert from "node:assert/strict";

import { encodeJsonRpcMessage, handleJsonRpcRequest } from "../server/agt-mcp.mjs";

import { loadPolicy } from "../lib/policy.mjs";

const state = await loadPolicy();
const STATELESS_META = {
  clientInfo: {
    name: "agt-parity-test",
    version: "1.0.0",
  },
  capabilities: {},
};

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

test("server/discover matches legacy capability and tool declarations", async () => {
  const initialize = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 10,
    method: "initialize",
    params: { protocolVersion: "2024-11-05" },
  });
  const listTools = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 11,
    method: "tools/list",
    params: {},
  });
  const discover = await handleJsonRpcRequest(state, {
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

test("stateless tools/list validates per-request _meta", async () => {
  const accepted = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 13,
    method: "tools/list",
    params: {},
    _meta: STATELESS_META,
  });
  const rejected = await handleJsonRpcRequest(state, {
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

test("stateless tools/call rejects missing caller identity after discovery", async () => {
  const discover = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 15,
    method: "server/discover",
    params: {},
    _meta: STATELESS_META,
  });
  const rejected = await handleJsonRpcRequest(state, {
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

test("stateless tools/call preserves caller context", async () => {
  const response = await handleJsonRpcRequest(state, {
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

test("legacy lifecycle remains compatible and terminal outcomes stay distinct", async () => {
  const initialize = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 18,
    method: "initialize",
    params: { protocolVersion: "2024-11-05" },
  });
  const initialized = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
  });
  const compatibilityFallback = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 19,
    method: "tools/call",
    params: {
      name: "agt_policy_status",
      arguments: {},
    },
  });
  const allow = await handleJsonRpcRequest(state, {
    jsonrpc: "2.0",
    id: 20,
    method: "tools/call",
    params: {
      name: "agt_policy_status",
      arguments: {},
    },
    _meta: STATELESS_META,
  });
  const deny = await handleJsonRpcRequest(state, {
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
  assert.equal(initialized, null);
  assert.equal(compatibilityFallback.result.isError, undefined);
  assert.notDeepEqual(allow.result, deny.error ?? deny.result);
  assert.notDeepEqual(allow.result, compatibilityFallback.result);
  assert.notDeepEqual(deny.error ?? deny.result, compatibilityFallback.result);
});
