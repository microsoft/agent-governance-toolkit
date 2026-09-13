// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * @agentmesh/mastra — Governance, trust, and audit middleware for Mastra agents.
 *
 * Provides native ACS policy enforcement plus trust and audit middleware:
 * - AgentControl: ACS manifest/runtime enforcement
 * - trustGate: Trust score verification before tool execution
 * - auditMiddleware: Tamper-evident audit logging with SHA-256 chain
 */

export { trustGate } from "./trust";
export { auditMiddleware, type AuditEntry } from "./audit";
export {
  type TrustConfig,
  type AuditConfig,
  type PolicyDecisionAudit,
  type TrustVerification,
} from "./types";
export { createGovernedTool } from "./governed-tool";
