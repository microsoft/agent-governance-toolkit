// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * OWASP Agentic Security Initiative (ASI) 2026 — risk catalogue.
 *
 * Reference: https://genai.owasp.org/agentic-security-initiative/
 * Catalogue: https://genai.owasp.org/agentic-risk/
 *
 * Migrated from legacy LLM Top-10 "ATxx" identifiers to the 2026 ASI
 * taxonomy ("ASIxx"). A backward-compatible lookup is provided so that
 * existing code referencing AT IDs continues to work.
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

/** OWASP Agentic Security Initiative 2026 — full ASI01–ASI11 catalogue. */
export const OWASP_AGENTIC_RISKS: Record<string, OwaspRisk> = {
  ASI01: {
    id: "ASI01",
    title: "Agent Goal Hijack",
    description:
      "Adversarial inputs override an agent's intended goal, causing it to pursue attacker-controlled objectives.",
    url: "https://genai.owasp.org/agentic-risk/asi01-agent-goal-hijack/",
  },
  ASI02: {
    id: "ASI02",
    title: "Tool Misuse and Exploitation",
    description:
      "An agent invokes tools in unintended or dangerous ways due to missing validation or inadequate access controls.",
    url: "https://genai.owasp.org/agentic-risk/asi02-tool-misuse-and-exploitation/",
  },
  ASI03: {
    id: "ASI03",
    title: "Identity and Privilege Abuse",
    description:
      "Agents acquire or exercise privileges beyond what their identity or role warrants, exposing sensitive data.",
    url: "https://genai.owasp.org/agentic-risk/asi03-identity-and-privilege-abuse/",
  },
  ASI04: {
    id: "ASI04",
    title: "Agentic Supply Chain Vulnerabilities",
    description:
      "Compromised dependencies, plugins, or sub-agents introduce malicious behaviour into the agent pipeline.",
    url: "https://genai.owasp.org/agentic-risk/asi04-agentic-supply-chain-vulnerabilities/",
  },
  ASI05: {
    id: "ASI05",
    title: "Unexpected Code Execution (RCE)",
    description:
      "Agent-driven code generation, deserialization, or eval paths achieve arbitrary code execution on the host.",
    url: "https://genai.owasp.org/agentic-risk/asi05-unexpected-code-execution/",
  },
  ASI06: {
    id: "ASI06",
    title: "Memory and Context Poisoning",
    description:
      "Persistent memory or context stores are manipulated so that future agent decisions are corrupted.",
    url: "https://genai.owasp.org/agentic-risk/asi06-memory-and-context-poisoning/",
  },
  ASI07: {
    id: "ASI07",
    title: "Insecure Inter-Agent Communication",
    description:
      "Messages between agents lack authentication, encryption, or integrity verification.",
    url: "https://genai.owasp.org/agentic-risk/asi07-insecure-inter-agent-communication/",
  },
  ASI08: {
    id: "ASI08",
    title: "Cascading Failures",
    description:
      "A failure in one agent or tool propagates through the system, causing widespread outage or resource exhaustion.",
    url: "https://genai.owasp.org/agentic-risk/asi08-cascading-failures/",
  },
  ASI09: {
    id: "ASI09",
    title: "Human-Agent Trust Exploitation",
    description:
      "Humans over-trust agent outputs, skip validation steps, or defer critical decisions to agents without oversight.",
    url: "https://genai.owasp.org/agentic-risk/asi09-human-agent-trust-exploitation/",
  },
  ASI10: {
    id: "ASI10",
    title: "Rogue Agents",
    description:
      "An agent deviates from its intended behaviour — due to poisoning, compromise, or misconfiguration — and acts against the operator's interests.",
    url: "https://genai.owasp.org/agentic-risk/asi10-rogue-agents/",
  },
  ASI11: {
    id: "ASI11",
    title: "Agent Untraceability",
    description:
      "Agent actions lack sufficient logging, provenance, or audit trails, making forensic analysis impossible.",
    url: "https://genai.owasp.org/agentic-risk/asi11-agent-untraceability/",
  },
};

/**
 * Backward-compatible mapping from legacy LLM Top-10 "AT" identifiers
 * to the primary ASI 2026 identifier.  Where a legacy ID maps to multiple
 * ASI risks, the first entry is the primary match.
 */
export const LEGACY_AT_TO_ASI: Record<string, string> = {
  AT01: "ASI01",
  AT02: "ASI02",
  AT03: "ASI10",
  AT05: "ASI04",
  AT06: "ASI03",
  AT07: "ASI02",
  AT08: "ASI01",
  AT09: "ASI09",
  AT10: "ASI08",
};

/**
 * Resolve a risk ID to its canonical ASI identifier.
 * Returns the ID unchanged if it already starts with "ASI", or maps it
 * via {@link LEGACY_AT_TO_ASI} if it is a legacy "AT" ID.
 */
function resolveId(id: string): string {
  if (id in OWASP_AGENTIC_RISKS) return id;
  return LEGACY_AT_TO_ASI[id] ?? id;
}

/**
 * Return OWASP risk objects for a list of risk IDs.
 * Accepts both ASI 2026 IDs (e.g. "ASI01") and legacy AT IDs (e.g. "AT01").
 * Unknown IDs are silently skipped.
 */
export function getOwaspRisks(ids: string[]): OwaspRisk[] {
  return ids
    .map((id) => OWASP_AGENTIC_RISKS[resolveId(id)])
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
