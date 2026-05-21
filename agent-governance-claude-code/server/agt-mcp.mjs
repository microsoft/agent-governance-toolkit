// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { fileURLToPath } from "node:url";
import path from "node:path";

import { checkArbitraryText, getPolicyStatus, loadPolicy } from "../lib/policy.mjs";

const VERSION = "3.6.0";
const PROTOCOL_VERSION = "2024-11-05";
const TOOL_DEFINITIONS = [
  {
    name: "agt_policy_status",
    description: "Return the active AGT Claude Code governance policy status and source.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "agt_policy_check_text",
    description: "Check text against AGT prompt, context-poisoning, and MCP-style threat detectors.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text to inspect.",
        },
      },
      required: ["text"],
      additionalProperties: false,
    },
  },
];

export async function handleJsonRpcRequest(state, request) {
  if (!request || typeof request !== "object" || request.jsonrpc !== "2.0") {
    return jsonRpcError(null, -32600, "Invalid Request");
  }

  const { id = null, method, params = {} } = request;

  if (typeof method !== "string") {
    return jsonRpcError(id, -32600, "Invalid Request");
  }

  if (method === "initialize") {
    const protocolVersion =
      typeof params.protocolVersion === "string" ? params.protocolVersion : PROTOCOL_VERSION;

    return jsonRpcResult(id, {
      protocolVersion,
      capabilities: {
        tools: {},
      },
      serverInfo: {
        name: "agt-governance",
        version: VERSION,
      },
    });
  }

  if (method === "notifications/initialized") {
    return null;
  }

  if (method === "ping") {
    return jsonRpcResult(id, {});
  }

  if (method === "tools/list") {
    return jsonRpcResult(id, { tools: TOOL_DEFINITIONS });
  }

  if (method === "tools/call") {
    return jsonRpcResult(id, await callTool(state, params));
  }

  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

export function encodeJsonRpcMessage(message) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

async function callTool(state, params) {
  const name = params?.name;
  const args = params?.arguments ?? {};

  if (name === "agt_policy_status") {
    return asJsonContent(await getPolicyStatus(state));
  }

  if (name === "agt_policy_check_text") {
    if (typeof args.text !== "string") {
      return asJsonError("agt_policy_check_text requires a string 'text' argument.");
    }

    return asJsonContent(checkArbitraryText(state, args.text, "mcp-check"));
  }

  return asJsonError(`Unknown tool: ${String(name)}`);
}

function asJsonContent(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

function asJsonError(message) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ error: message }, null, 2),
      },
    ],
    isError: true,
  };
}

function jsonRpcResult(id, result) {
  return {
    jsonrpc: "2.0",
    id,
    result,
  };
}

function jsonRpcError(id, code, message) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
    },
  };
}

async function startServer() {
  const state = await loadPolicy();
  let buffer = "";

  process.stdin.setEncoding("utf8");
  process.stdin.on("data", async (chunk) => {
    buffer += chunk;
    try {
      buffer = await drainBuffer(state, buffer);
    } catch (error) {
      const response = jsonRpcError(null, -32603, error instanceof Error ? error.message : String(error));
      process.stdout.write(encodeJsonRpcMessage(response));
      buffer = "";
    }
  });
}

async function drainBuffer(state, buffer) {
  let remaining = buffer;

  while (remaining.length > 0) {
    const headerEnd = remaining.indexOf("\r\n\r\n");
    if (headerEnd >= 0) {
      const headerBlock = remaining.slice(0, headerEnd);
      const lengthMatch = /Content-Length:\s*(\d+)/i.exec(headerBlock);
      if (!lengthMatch) {
        throw new Error("Missing Content-Length header");
      }

      const bodyStart = headerEnd + 4;
      const bodyLength = Number(lengthMatch[1]);
      if (remaining.length < bodyStart + bodyLength) {
        return remaining;
      }

      const body = remaining.slice(bodyStart, bodyStart + bodyLength);
      remaining = remaining.slice(bodyStart + bodyLength);
      await respondToBody(state, body);
      continue;
    }

    const newlineIndex = remaining.indexOf("\n");
    if (newlineIndex < 0) {
      return remaining;
    }

    const line = remaining.slice(0, newlineIndex).trim();
    remaining = remaining.slice(newlineIndex + 1);
    if (line.length === 0) {
      continue;
    }

    await respondToBody(state, line);
  }

  return remaining;
}

async function respondToBody(state, body) {
  let request;
  try {
    request = JSON.parse(body);
  } catch {
    process.stdout.write(encodeJsonRpcMessage(jsonRpcError(null, -32700, "Parse error")));
    return;
  }

  const response = await handleJsonRpcRequest(state, request);
  if (response) {
    process.stdout.write(encodeJsonRpcMessage(response));
  }
}

if (isMainModule(import.meta.url)) {
  await startServer();
}

function isMainModule(moduleUrl) {
  if (!process.argv[1]) {
    return false;
  }

  return fileURLToPath(moduleUrl) === path.resolve(process.argv[1]);
}
