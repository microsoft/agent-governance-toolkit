// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { fileURLToPath } from "node:url";

import { checkArbitraryText, formatPolicySummary, getPolicyStatus, loadPolicy } from "../lib/policy.mjs";

const SERVER_INFO = {
  name: "agt-global-policy",
  version: "3.3.0",
};
const PROTOCOL_VERSION = "2024-11-05";
const JSONRPC_VERSION = "2.0";
const HEADER_SEPARATOR = Buffer.from("\r\n\r\n", "utf8");
const extensionRoot = fileURLToPath(new URL("..", import.meta.url));

const tools = [
  {
    name: "agt_policy_status",
    description: "Return the active AGT Antigravity policy runtime status and summary.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "agt_policy_check_text",
    description: "Run AGT poisoning, MCP, and prompt-defense checks against arbitrary text.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The text to inspect.",
        },
      },
      required: ["text"],
      additionalProperties: false,
    },
  },
];

let inputBuffer = Buffer.alloc(0);

process.stdin.on("data", (chunk) => {
  inputBuffer = Buffer.concat([inputBuffer, chunk]);
  void drainInputBuffer();
});

async function drainInputBuffer() {
  while (true) {
    const headerEnd = inputBuffer.indexOf(HEADER_SEPARATOR);
    if (headerEnd === -1) {
      return;
    }

    const headerText = inputBuffer.subarray(0, headerEnd).toString("utf8");
    const contentLength = getContentLength(headerText);
    if (contentLength === null) {
      inputBuffer = Buffer.alloc(0);
      writeError(null, -32700, "Missing or invalid Content-Length header.");
      return;
    }

    const messageStart = headerEnd + HEADER_SEPARATOR.length;
    const messageEnd = messageStart + contentLength;
    if (inputBuffer.length < messageEnd) {
      return;
    }

    const payload = inputBuffer.subarray(messageStart, messageEnd).toString("utf8");
    inputBuffer = inputBuffer.subarray(messageEnd);

    let message;
    try {
      message = JSON.parse(payload);
    } catch {
      writeError(null, -32700, "Invalid JSON payload.");
      continue;
    }

    await handleMessage(message);
  }
}

function getContentLength(headerText) {
  for (const line of headerText.split("\r\n")) {
    const [name, ...valueParts] = line.split(":");
    if (name?.toLowerCase() !== "content-length") {
      continue;
    }
    const parsed = Number.parseInt(valueParts.join(":").trim(), 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

async function handleMessage(message) {
  if (message?.jsonrpc !== JSONRPC_VERSION || typeof message?.method !== "string") {
    writeError(message?.id ?? null, -32600, "Invalid JSON-RPC request.");
    return;
  }

  if (message.method === "notifications/initialized") {
    return;
  }

  try {
    if (message.method === "initialize") {
      writeResult(message.id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: {},
        },
        serverInfo: SERVER_INFO,
      });
      return;
    }

    if (message.method === "ping") {
      writeResult(message.id, {});
      return;
    }

    if (message.method === "tools/list") {
      writeResult(message.id, { tools });
      return;
    }

    if (message.method === "tools/call") {
      writeResult(message.id, await callTool(message.params ?? {}));
      return;
    }

    writeError(message.id ?? null, -32601, `Unknown method: ${message.method}`);
  } catch (error) {
    writeError(message.id ?? null, -32603, error instanceof Error ? error.message : String(error));
  }
}

async function callTool(params) {
  const state = await loadPolicy({ extensionRoot });
  const args = params.arguments ?? {};

  if (params.name === "agt_policy_status") {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              summary: formatPolicySummary(state),
              status: getPolicyStatus(state),
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  if (params.name === "agt_policy_check_text") {
    const text = String(args.text ?? "").trim();
    if (!text) {
      return {
        content: [
          {
            type: "text",
            text: "The `text` argument is required.",
          },
        ],
        isError: true,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(checkArbitraryText(state, text), null, 2),
        },
      ],
    };
  }

  return {
    content: [
      {
        type: "text",
        text: `Unknown tool: ${params.name}`,
      },
    ],
    isError: true,
  };
}

function writeResult(id, result) {
  if (id === undefined || id === null) {
    return;
  }
  writeMessage({
    jsonrpc: JSONRPC_VERSION,
    id,
    result,
  });
}

function writeError(id, code, message) {
  writeMessage({
    jsonrpc: JSONRPC_VERSION,
    id,
    error: {
      code,
      message,
    },
  });
}

function writeMessage(payload) {
  const body = JSON.stringify(payload);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`);
}
