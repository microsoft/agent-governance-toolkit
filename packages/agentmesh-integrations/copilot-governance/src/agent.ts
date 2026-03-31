// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * GitHub Copilot Extension — agent request handler.
 *
 * Parses the incoming Copilot agent request, routes to the appropriate
 * review function, and returns a streamed SSE response.
 *
 * The Copilot agent protocol sends a POST body like:
 * ```json
 * {
 *   "messages": [
 *     { "role": "user", "content": "@governance review\n```ts\n...code...\n```" }
 *   ]
 * }
 * ```
 *
 * Supported commands (prefix of the last user message):
 *   @governance review      — Review the attached code block
 *   @governance validate    — Validate the attached YAML policy block
 *   @governance owasp       — Show OWASP Agentic Top-10 risk summary
 *   @governance help        — Show usage instructions
 *
 * All other messages get a helpful fallback.
 */

import { reviewCode, formatReviewResult } from "./reviewer";
import { validatePolicy, formatPolicyValidation } from "./policy-validator";
import { OWASP_AGENTIC_RISKS } from "./owasp";
import type { AgentRequest, AgentResponseToken } from "./types";

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/** Extract the content of the first fenced code block in a message. */
function extractCodeBlock(text: string): string | null {
  const match = text.match(/```(?:\w+)?\n([\s\S]*?)```/);
  return match ? match[1] : null;
}

/** Detect the command from the last user message. */
function detectCommand(content: string): string {
  const lower = content.toLowerCase();
  if (/\breview\b/.test(lower)) return "review";
  if (/\bvalidate\b/.test(lower)) return "validate";
  if (/\bowasp\b/.test(lower)) return "owasp";
  if (/\bhelp\b/.test(lower)) return "help";
  // If a code block is present without an explicit command, default to review
  if (/```/.test(content)) return "review";
  return "help";
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

function buildHelpResponse(): string {
  return [
    "## 🛡️ Agent Governance Copilot Extension",
    "",
    "I review agent code for governance gaps and validate policy YAML files.",
    "",
    "### Commands",
    "",
    "| Command | What it does |",
    "|---------|-------------|",
    "| `@governance review` | Review a code block for governance gaps |",
    "| `@governance validate` | Validate a governance policy YAML block |",
    "| `@governance owasp` | Show OWASP Agentic Top-10 risk catalogue |",
    "| `@governance help` | Show this message |",
    "",
    "### Quick Example",
    "",
    "Paste your agent code and ask me to review it:",
    "",
    "````",
    "@governance review",
    "```ts",
    "const result = await myTool.execute({ query: userInput });",
    "```",
    "````",
    "",
    "I will identify missing governance middleware, unguarded tool calls,",
    "missing audit logs, and more — and link each finding to the relevant",
    "OWASP Agentic Top-10 risk.",
  ].join("\n");
}

function buildOwaspResponse(): string {
  const lines = [
    "## OWASP Agentic Top-10 — Governance Relevance",
    "",
    "The following risks are most relevant to agent governance:",
    "",
  ];
  for (const risk of Object.values(OWASP_AGENTIC_RISKS)) {
    lines.push(`### [${risk.id}] ${risk.title}`);
    lines.push(risk.description);
    lines.push(`→ ${risk.url}`);
    lines.push("");
  }
  lines.push(
    "> Mitigate these risks by adding governance middleware from the " +
      "[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)."
  );
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Handle a GitHub Copilot Extension agent request.
 *
 * @param request - The parsed AgentRequest from the Copilot endpoint.
 * @returns An async generator of response tokens (for SSE streaming).
 *
 * @example
 * ```ts
 * import { handleAgentRequest } from '@agentmesh/copilot-governance';
 *
 * for await (const token of handleAgentRequest(parsedBody)) {
 *   res.write(`data: ${JSON.stringify(token)}\n\n`);
 * }
 * ```
 */
export async function* handleAgentRequest(
  request: AgentRequest
): AsyncGenerator<AgentResponseToken> {
  // Find the last user message
  const lastUser = [...request.messages].reverse().find((m) => m.role === "user");
  const content = lastUser?.content ?? "";

  const command = detectCommand(content);
  let responseText: string;

  switch (command) {
    case "review": {
      const code = extractCodeBlock(content) ?? content;
      const result = reviewCode(code);
      responseText = formatReviewResult(result);
      break;
    }
    case "validate": {
      const block = extractCodeBlock(content);
      if (!block) {
        responseText =
          "⚠️ No YAML block found. Please paste your policy YAML in a fenced code block:\n\n" +
          "````\n@governance validate\n```yaml\npolicy:\n  name: my-policy\n  ...\n```\n````";
      } else {
        let parsed: unknown;
        try {
          parsed = parseYamlLite(block);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          responseText = `❌ Could not parse YAML: ${msg}\n\nPlease check for syntax errors.`;
          break;
        }
        const result = validatePolicy(parsed);
        responseText = formatPolicyValidation(result);
      }
      break;
    }
    case "owasp":
      responseText = buildOwaspResponse();
      break;
    default:
      responseText = buildHelpResponse();
  }

  // Stream the response word-by-word to simulate typing
  yield* streamText(responseText);
}

/** Yield tokens from a complete response string. */
async function* streamText(text: string): AsyncGenerator<AgentResponseToken> {
  // Split on word boundaries while preserving whitespace
  const tokens = text.match(/\S+|\s+/g) ?? [text];
  for (const token of tokens) {
    yield { content: token };
  }
}

// ---------------------------------------------------------------------------
// Minimal YAML parser (handles the subset used by governance policies)
// ---------------------------------------------------------------------------

/**
 * Extremely minimal YAML-to-object parser.
 *
 * Supports the strict subset used by governance policy files:
 * - Simple key: value mappings
 * - Nested mappings (indentation-based)
 * - String, integer, boolean, and null scalars
 * - Inline lists: [a, b, c]
 * - Block lists:
 *     - item
 *
 * Does NOT support anchors, aliases, multi-document streams, or complex types.
 * For production use, replace with a proper YAML library such as `js-yaml`.
 */
export function parseYamlLite(text: string): unknown {
  const lines = text.split("\n");
  const result = parseBlock(lines, 0, 0);
  return result.value;
}

interface ParseResult {
  value: unknown;
  nextLine: number;
}

function parseBlock(lines: string[], startLine: number, expectedIndent: number): ParseResult {
  const obj: Record<string, unknown> = {};
  let i = startLine;

  while (i < lines.length) {
    const raw = lines[i];
    const trimmed = raw.trimEnd();

    // Skip blank lines and comments
    if (trimmed.trim() === "" || trimmed.trim().startsWith("#")) {
      i++;
      continue;
    }

    const indent = raw.length - raw.trimStart().length;

    // If indentation decreases, we've left this block
    if (indent < expectedIndent) break;
    if (indent > expectedIndent) {
      // Unexpected deeper indent — skip
      i++;
      continue;
    }

    const line = trimmed.trim();

    // Block list item
    if (line.startsWith("- ")) {
      // Caller should handle this as a list
      break;
    }

    // Key: value pair
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) {
      i++;
      continue;
    }

    const key = line.slice(0, colonIdx).trim();
    const rest = line.slice(colonIdx + 1).trim();

    if (rest === "" || rest === "|" || rest === ">") {
      // Value is on next lines — parse as nested block or list
      i++;
      const nextIndent = getNextIndent(lines, i);
      if (nextIndent === null) {
        obj[key] = null;
        continue;
      }
      const nextLine = lines[i]?.trim() ?? "";
      if (nextLine.startsWith("- ")) {
        // Block list
        const listResult = parseList(lines, i, nextIndent);
        obj[key] = listResult.value;
        i = listResult.nextLine;
      } else {
        // Nested mapping
        const blockResult = parseBlock(lines, i, nextIndent);
        obj[key] = blockResult.value;
        i = blockResult.nextLine;
      }
    } else {
      obj[key] = parseScalar(rest);
      i++;
    }
  }

  return { value: obj, nextLine: i };
}

function parseList(lines: string[], startLine: number, expectedIndent: number): ParseResult {
  const arr: unknown[] = [];
  let i = startLine;

  while (i < lines.length) {
    const raw = lines[i];
    const trimmed = raw.trimEnd();
    if (trimmed.trim() === "" || trimmed.trim().startsWith("#")) {
      i++;
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    if (indent < expectedIndent) break;
    const line = trimmed.trim();
    if (!line.startsWith("- ")) break;
    arr.push(parseScalar(line.slice(2).trim()));
    i++;
  }

  return { value: arr, nextLine: i };
}

function getNextIndent(lines: string[], from: number): number | null {
  for (let i = from; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    return raw.length - raw.trimStart().length;
  }
  return null;
}

function parseScalar(value: string): unknown {
  // Inline list [a, b, c]
  if (value.startsWith("[") && value.endsWith("]")) {
    const inner = value.slice(1, -1);
    return inner
      .split(",")
      .map((s) => parseScalar(s.trim()))
      .filter((s) => s !== "");
  }
  // Null
  if (value === "" || value === "null" || value === "~") return null;
  // Boolean
  if (value === "true") return true;
  if (value === "false") return false;
  // Number
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
  // String — strip surrounding quotes
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}
