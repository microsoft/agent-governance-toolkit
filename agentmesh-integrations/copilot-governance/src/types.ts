// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Shared types for the GitHub Copilot governance extension.
 */

/** Severity of a governance finding. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** A single governance finding from code review. */
export interface ReviewFinding {
  /** Short rule identifier, e.g. "missing-audit-logging". */
  ruleId: string;
  /** Human-readable title. */
  title: string;
  /** Detailed description of the issue. */
  description: string;
  /** Severity level. */
  severity: Severity;
  /** Line number in the analysed source, if known. */
  line?: number;
  /** Suggested fix or code snippet. */
  suggestion?: string;
  /** Related OWASP ASI 2026 risk IDs, e.g. ["ASI01"]. */
  owaspRisks: string[];
}

/** Aggregated result of a governance code review. */
export interface ReviewResult {
  /** All findings from the review. */
  findings: ReviewFinding[];
  /** Whether the code passes the governance baseline. */
  passed: boolean;
  /** Brief summary suitable for a Copilot chat reply. */
  summary: string;
}

/** A single finding from YAML policy validation. */
export interface PolicyFinding {
  /** Field path that has the issue, e.g. "policy.tools[0].name". */
  field: string;
  /** Human-readable message. */
  message: string;
  /** Severity of this finding. */
  severity: Severity;
}

/** Result of validating a governance policy YAML file. */
export interface PolicyValidationResult {
  /** Whether the policy is valid. */
  valid: boolean;
  /** All validation findings. */
  findings: PolicyFinding[];
  /** Brief summary of the validation. */
  summary: string;
}

/** A message in the Copilot conversation. */
export interface CopilotMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

/** Parsed request from the GitHub Copilot Extension agent endpoint. */
export interface AgentRequest {
  messages: CopilotMessage[];
}

/** Single token in an SSE agent response stream. */
export interface AgentResponseToken {
  content: string;
}
