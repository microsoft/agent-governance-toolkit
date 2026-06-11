// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Shared sanitization helpers for the AI agent runner.
//
// This file is consumed two ways:
//   1. At runtime, ``action.yml`` concatenates it ahead of the generated
//      ``ai-agent-runner.mjs`` body so the helpers below are in scope.
//   2. At test time, ``tests/ci/test_ai_agent_sanitize.py`` spawns a Node
//      child process that imports the named exports directly.
//
// The AI agent's output is **untrusted**: a malicious PR title, body, diff,
// comment, or upstream model response can contain ANSI escapes, bidi controls,
// zero-width chars, HTML/Markdown injection, GitHub or Azure workflow
// commands, @-mentions, OSC-8 hyperlinks, and prompt-injection payloads.
// Everything that flows back into a PR comment, summary, or workflow output
// goes through ``sanitizeForComment`` first; everything that might flow into a
// shell ``run:`` block must go through ``toShellSafe`` (base64).

export const MAX_COMMENT_BYTES = 60000;
export const MAX_SUMMARY_BYTES = 180;

// Bidi formatting controls (LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI) and
// zero-width chars (ZWSP/ZWNJ/ZWJ/WJ/BOM). These can reorder visible text
// after rendering and silently split tokens like ``@user`` so they survive a
// naive regex. Strip unconditionally.
const INVISIBLE_CONTROLS = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/g;

// ANSI CSI / SGR sequences (colors, cursor moves).
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// OSC-8 hyperlink: ``ESC ] 8 ; <params> ; <url> BEL <label> ESC ] 8 ;; BEL``.
// Some terminals render the label as a clickable link to ``<url>`` — a clean
// vector for tricking maintainers into visiting attacker-controlled hosts.
const OSC8 = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
// C1 control codes (U+0080..U+009F) — never useful in a comment body.
const ANSI_C1 = /[\u0080-\u009F]/g;

// HTML comments. A single non-global pass is incomplete because nested or
// overlapping comment markers (e.g. ``<!-- <!-- x --> -->``) reduce to
// ``<!-- ... -->`` again after one substitution. We loop until the regex no
// longer matches so no comment markers survive into the escaping step below.
// (The final ``<``/``>`` escape would defang any survivors, but iterative
// stripping also removes the comment-injection vector noted by CodeQL
// js/incomplete-multi-character-sanitization.)
const HTML_COMMENT = /<!--[\s\S]*?-->/g;
function stripHtmlComments(text) {
  let prev;
  let current = text;
  do {
    prev = current;
    current = current.replace(HTML_COMMENT, "");
  } while (current !== prev);
  return current;
}

export function truncateUtf8(value, maxBytes) {
  const text = String(value || "");
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const suffix = "\n\n... [AI output truncated by workflow safety limit] ...";
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  let truncated = Buffer.from(text, "utf8")
    .subarray(0, Math.max(0, maxBytes - suffixBytes))
    .toString("utf8")
    .replace(/\uFFFD+$/g, "");
  while (Buffer.byteLength(truncated + suffix, "utf8") > maxBytes) {
    truncated = truncated.slice(0, -1);
  }
  return truncated + suffix;
}

// Neutralize @-mentions in every encoding GitHub will render:
//   - plain ASCII ``@`` (U+0040)
//   - HTML entities ``&#64;`` (decimal) and ``&#x40;`` (hex)
//   - Unicode fullwidth ``＠`` (U+FF20) — collapsed to ``@`` by NFKC, but we
//     also match it directly in case NFKC was skipped upstream
// We strip ``INVISIBLE_CONTROLS`` first so an attacker cannot inject
// ``@<ZWSP>user`` and have it re-form as ``@user`` after a downstream
// renderer drops zero-width chars.
export function neutralizeMentions(text) {
  return String(text || "")
    .replace(INVISIBLE_CONTROLS, "")
    .replace(/(?:@|＠|&#0*64;|&#[xX]0*40;)([A-Za-z0-9][A-Za-z0-9-]{0,38})/g, "`@`$1");
}

export function sanitizeForComment(text, maxBytes = MAX_COMMENT_BYTES) {
  // NFKC-normalize so compatibility variants (fullwidth digits and letters,
  // ligatures) cannot bypass the character-class filters below by encoding
  // workflow-command markers like ``::`` in fullwidth form.
  const normalized = String(text || "").normalize("NFKC");
  const stripped = stripHtmlComments(
    normalized
      .replace(OSC8, "")
      .replace(ANSI_CSI, "")
      .replace(ANSI_C1, "")
      .replace(INVISIBLE_CONTROLS, ""),
  );
  const cleaned = stripped
    .split(/\r?\n/)
    .filter((line) => !/^::[A-Za-z0-9_-]+(?:\s|::)/.test(line))
    .filter((line) => !/^##\[[A-Za-z][^\]]*\]/.test(line))
    .join("\n")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  const safe = neutralizeMentions(cleaned).trim();
  return truncateUtf8(safe || "AI analysis returned no displayable content.", maxBytes);
}

// Returns ``text`` base64-encoded for safe consumption inside a shell
// ``run:`` block. The intended pattern is:
//
//     run: |
//       decoded=$(printf '%s' "${{ steps.ai.outputs.response-shell-safe }}" | base64 -d)
//       printf '%s' "$decoded" > somefile
//
// The plain ``response`` output MUST NOT be wired into a shell ``run:`` even
// after ``sanitizeForComment`` — sanitized comment text can still contain
// backticks, ``$`` expansions, newlines, and command-substitution patterns
// that have shell meaning. Base64 reduces the payload to the fixed alphabet
// ``[A-Za-z0-9+/=]`` so quoting in the consumer is sufficient.
export function toShellSafe(text) {
  return Buffer.from(String(text || ""), "utf8").toString("base64");
}
