// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * @agentmesh/copilot-governance — GitHub Copilot Extension for agent governance review.
 *
 * Exports three public surfaces:
 *
 * 1. **reviewer** — `reviewCode(source)` scans agent source code for governance gaps
 *    and returns structured findings with OWASP risk links.
 *
 * 2. **policy-validator** — `validatePolicy(obj)` validates a parsed governance
 *    policy YAML against the AgentMesh policy schema.
 *
 * 3. **agent** — `handleAgentRequest(request)` is the async generator that drives
 *    the Copilot Extension SSE stream. Wire it to your HTTP server.
 *
 * 4. **owasp** — `OWASP_AGENTIC_RISKS` and helpers for formatting risk references.
 */

export { reviewCode, formatReviewResult } from "./reviewer";
export { validatePolicy, formatPolicyValidation } from "./policy-validator";
export { handleAgentRequest, parseYamlLite } from "./agent";
export { OWASP_AGENTIC_RISKS, getOwaspRisks, formatOwaspRisks } from "./owasp";
export type {
  ReviewFinding,
  ReviewResult,
  PolicyFinding,
  PolicyValidationResult,
  CopilotMessage,
  AgentRequest,
  AgentResponseToken,
  Severity,
} from "./types";
