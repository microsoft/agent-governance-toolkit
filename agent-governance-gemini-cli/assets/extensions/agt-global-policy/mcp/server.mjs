// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "node:url";

import { checkArbitraryText, formatPolicySummary, getPolicyStatus, loadPolicy } from "../lib/policy.mjs";

const server = new Server(
  {
    name: "agt-global-policy",
    version: "3.6.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "agt_policy_status",
      description: "Return the active AGT Gemini policy runtime status and summary.",
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
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const state = await loadPolicy({
    extensionRoot: fileURLToPath(new URL("..", import.meta.url)),
  });
  const args = request.params.arguments ?? {};

  if (request.params.name === "agt_policy_status") {
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

  if (request.params.name === "agt_policy_check_text") {
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
        text: `Unknown tool: ${request.params.name}`,
      },
    ],
    isError: true,
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
