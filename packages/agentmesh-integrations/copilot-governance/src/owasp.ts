// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * OWASP Agentic Security Initiative — Agentic Top-10 risk catalogue.
 *
 * Reference: https://genai.owasp.org/llm-top-10/
 * Agentic extension: https://owasp.org/www-project-top-10-for-large-language-model-applications/
 */

export interface OwaspRisk {
  /** Risk identifier, e.g. "AT01". */
  id: string;
  /** Short title. */
  title: string;
  /** One-line description. */
  description: string;
  /** URL to the OWASP guidance page. */
  url: string;
}

/** OWASP Agentic Top-10 risks most relevant to agent governance. */
export const OWASP_AGENTIC_RISKS: Record<string, OwaspRisk> = {
  AT01: {
    id: "AT01",
    title: "Prompt Injection",
    description:
      "Malicious content in inputs hijacks agent actions by overriding original instructions.",
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  },
  AT02: {
    id: "AT02",
    title: "Insecure Output Handling",
    description:
      "Agent outputs are passed to downstream components without validation or sanitisation.",
    url: "https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/",
  },
  AT06: {
    id: "AT06",
    title: "Sensitive Information Disclosure",
    description:
      "PII or secrets are leaked in agent inputs, outputs, or audit logs.",
    url: "https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/",
  },
  AT07: {
    id: "AT07",
    title: "Insecure Plugin / Tool Design",
    description:
      "Tools lack authorisation, input validation, or allow-listing, enabling privilege escalation.",
    url: "https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/",
  },
  AT08: {
    id: "AT08",
    title: "Excessive Agency",
    description:
      "Agent is granted more permissions or capabilities than required for its task.",
    url: "https://genai.owasp.org/llmrisk/llm08-excessive-agency/",
  },
  AT09: {
    id: "AT09",
    title: "Overreliance",
    description:
      "Humans over-trust agent outputs without proper validation or audit trails.",
    url: "https://genai.owasp.org/llmrisk/llm09-overreliance/",
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
