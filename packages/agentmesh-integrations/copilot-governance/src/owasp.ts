// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * OWASP Agentic Security Initiative — Agentic Top-10 risk catalogue.
 *
 * Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
 */

export interface OwaspRisk {
  /** Risk identifier, e.g. "ASI01". */
  id: string;
  /** Short title. */
  title: string;
  /** One-line description. */
  description: string;
  /** URL to the OWASP guidance page. */
  url: string;
}

const OWASP_AGENTIC_TOP_10_2026_URL_BASE =
  "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";

/** Canonical OWASP Agentic Top-10 2026 risks keyed by ASI identifier. */
export const OWASP_AGENTIC_RISKS: Record<string, OwaspRisk> = {
  ASI01: {
    id: "ASI01",
    title: "Agent Goal Hijack",
    description:
      "Attackers manipulate the agent's instructions to divert it from its original objective via indirect prompt injection.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI02: {
    id: "ASI02",
    title: "Tool Misuse & Exploitation",
    description:
      "Agents misuse legitimate tools due to ambiguous, manipulated, or malicious input.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI03: {
    id: "ASI03",
    title: "Identity & Privilege Abuse",
    description:
      "Agents inherit or escalate privileges by leaking, reusing, or mishandling credentials or session tokens.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI04: {
    id: "ASI04",
    title: "Agentic Supply Chain Vulnerabilities",
    description:
      "Compromised or malicious tools, models, plugins, MCP servers, or prompts injected into agent workflows.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI05: {
    id: "ASI05",
    title: "Unexpected Code Execution (RCE)",
    description:
      "Agents generate and execute untrusted code or commands.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI06: {
    id: "ASI06",
    title: "Memory & Context Poisoning",
    description:
      "Attackers inject malicious data into an agent's persistent memory or context, affecting future reasoning.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI07: {
    id: "ASI07",
    title: "Insecure Inter-Agent Communication",
    description:
      "Communication between agents lacks authentication, encryption, or schema validation.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI08: {
    id: "ASI08",
    title: "Cascading Failures",
    description:
      "Failures in one agent or component propagate unpredictably, causing widespread system harm.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI09: {
    id: "ASI09",
    title: "Human-Agent Trust Exploitation",
    description:
      "Attackers abuse human trust in AI agents to persuade users to approve unauthorized actions.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
  ASI10: {
    id: "ASI10",
    title: "Rogue Agents",
    description:
      "Malicious, compromised, or self-propagating agents perform unauthorized activities.",
    url: OWASP_AGENTIC_TOP_10_2026_URL_BASE,
  },
};

/**
 * Return OWASP risk objects for a list of risk IDs.
 * Unknown IDs are silently skipped.
 */
export function getOwaspRisks(ids: string[]): OwaspRisk[] {
  return ids
    .map((id) => OWASP_AGENTIC_RISKS[id])
    .filter((r): r is OwaspRisk => r !== undefined);
}

/**
 * Format OWASP risk references as a Markdown list.
 */
export function formatOwaspRisks(ids: string[]): string {
  const risks = getOwaspRisks(ids);
  if (risks.length === 0) return "";
  return risks
    .map((r) => `- **[${r.id}] ${r.title}**: ${r.description}\n  → ${r.url}`)
    .join("\n");
}
