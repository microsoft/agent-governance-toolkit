// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * @agentmesh/mastra — Governance, trust, and audit middleware for Mastra agents.
 *
 * Provides three middleware layers:
 * - governanceMiddleware: Policy enforcement (rate limits, content filtering, PII)
 * - trustGate: Trust score verification before tool execution
 * - auditMiddleware: Tamper-evident audit logging with SHA-256 chain
 */

export { governanceMiddleware } from "./governance";
export { trustGate } from "./trust";
export { auditMiddleware, type AuditEntry } from "./audit";
export {
  type GovernancePolicy,
  type TrustConfig,
  type AuditConfig,
  type GovernanceResult,
  type TrustVerification,
} from "./types";
export { createGovernedTool } from "./governed-tool";
