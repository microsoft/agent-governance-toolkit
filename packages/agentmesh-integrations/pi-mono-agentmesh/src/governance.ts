// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { readFile } from "fs/promises";
import {
  AgentIdentity,
  AuditLogger,
  PolicyEngine,
  type AuditEntry,
  type PolicyDecision,
  type PolicyRule,
} from "@microsoft/agentmesh-sdk";

export type PiGovernanceVerdict = "allow" | "deny" | "review";

export interface PiGovernanceDecision {
  verdict: PiGovernanceVerdict;
  reason: string;
  matchedRule?: string;
  source: "policy" | "bash-safety";
}

export interface PiGovernanceAuditRecord {
  kind: "prompt" | "tool_call" | "tool_result" | "provider_request";
  timestamp: string;
  action: string;
  decision?: PiGovernanceDecision;
  input?: unknown;
  output?: unknown;
  metadata?: Record<string, unknown>;
  auditEntry: AuditEntry;
}

export interface PiGovernanceConfig {
  agentId?: string;
  capabilities?: string[];
  policyRules?: PolicyRule[];
  policyPath?: string;
  maxAuditEntries?: number;
}

export interface PiGovernanceLogger {
  warn?(scope: string, message: string, data?: Record<string, unknown>): void;
}

const DEFAULT_CAPABILITIES = [
  "read",
  "grep",
  "find",
  "ls",
  "edit",
  "write",
  "bash",
];

const DEFAULT_POLICY_RULES: PolicyRule[] = [
  { action: "read", effect: "allow" },
  { action: "grep", effect: "allow" },
  { action: "find", effect: "allow" },
  { action: "ls", effect: "allow" },
  { action: "edit", effect: "allow" },
  { action: "write", effect: "allow" },
  { action: "bash", effect: "allow" },
  { action: "*", effect: "deny" },
];

const BASH_DENY_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /(^|\s)rm\s+-rf\s+\/(\s|$)/i, reason: "recursive root deletion" },
  { pattern: /(^|\s)mkfs(\s|$)/i, reason: "filesystem format attempt" },
  { pattern: /(^|\s)dd\s+if=/i, reason: "raw disk write attempt" },
  { pattern: /:\(\)\s*\{/i, reason: "fork bomb pattern" },
  { pattern: /(^|\s)(shutdown|reboot|halt)(\s|$)/i, reason: "system shutdown command" },
  { pattern: /(^|\s)(ncat|nc)\s+-l(\s|$)/i, reason: "listener or reverse shell pattern" },
  { pattern: /curl\b.*(\s--data|\s-d\s)/i, reason: "data exfiltration via curl POST" },
  { pattern: /wget\b.*--post/i, reason: "data exfiltration via wget POST" },
];

const BASH_REVIEW_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /(^|\s)git\s+push(\s|$)/i, reason: "pushing to a remote repository" },
  { pattern: /(^|\s)npm\s+publish(\s|$)/i, reason: "publishing a package" },
  { pattern: /(^|\s)docker\s+push(\s|$)/i, reason: "pushing a container image" },
];

export class PiAgentMeshGovernance {
  private readonly identity: AgentIdentity;
  private readonly policyEngine: PolicyEngine;
  private readonly auditLogger: AuditLogger;
  private readonly auditRecords: PiGovernanceAuditRecord[] = [];

  constructor(private readonly config: PiGovernanceConfig = {}) {
    this.identity = AgentIdentity.generate(
      config.agentId || "pi-mono-agent",
      config.capabilities || DEFAULT_CAPABILITIES,
      {
        name: "Pi Mono Agent",
        description: "pi-mono coding agent governed by AgentMesh policy checks",
      }
    );
    this.policyEngine = new PolicyEngine(config.policyRules || DEFAULT_POLICY_RULES);
    this.auditLogger = new AuditLogger({
      maxEntries: config.maxAuditEntries || 10_000,
    });
  }

  get agentDid(): string {
    return this.identity.did;
  }

  async initialize(): Promise<void> {
    if (!this.config.policyPath) {
      return;
    }

    const policyContents = await readFile(this.config.policyPath, "utf-8");
    if (this.config.policyPath.endsWith(".json")) {
      this.policyEngine.loadJson(policyContents);
      return;
    }
    this.policyEngine.loadYaml(policyContents);
  }

  evaluateToolCall(
    toolName: string,
    input?: Record<string, unknown>
  ): PiGovernanceDecision {
    const policyDecision = this.policyEngine.evaluate(toolName, {
      toolName,
      ...flattenContext(input),
    });

    let decision = this.fromPolicyDecision(policyDecision, toolName);

    if (decision.verdict === "allow" && toolName === "bash") {
      decision = this.evaluateBashSafety(input);
    }

    this.record("tool_call", toolName, {
      decision,
      input,
      metadata: {
        toolName,
      },
    });

    return decision;
  }

  recordPrompt(prompt: string, hasImages: boolean): void {
    this.record("prompt", "prompt", {
      input: {
        promptLength: prompt.length,
        preview: prompt.slice(0, 500),
      },
      metadata: {
        hasImages,
      },
    });
  }

  recordToolResult(
    toolName: string,
    input: Record<string, unknown> | undefined,
    result: {
      content?: unknown;
      isError?: boolean;
      details?: unknown;
    }
  ): void {
    this.record("tool_result", toolName, {
      input,
      output: summarizeToolResult(result.content),
      metadata: {
        isError: !!result.isError,
        hasDetails: result.details !== undefined,
      },
    });
  }

  recordProviderRequest(payload: unknown): void {
    const safePayload =
      payload && typeof payload === "object"
        ? {
            model: (payload as Record<string, unknown>).model,
            messageCount: Array.isArray((payload as Record<string, unknown>).messages)
              ? ((payload as Record<string, unknown>).messages as unknown[]).length
              : undefined,
          }
        : { type: typeof payload };

    this.record("provider_request", "provider_request", {
      input: safePayload,
    });
  }

  getAuditLog(): PiGovernanceAuditRecord[] {
    return [...this.auditRecords];
  }

  verifyAuditLog(): boolean {
    return this.auditLogger.verify();
  }

  createBlockedToolResult(
    decision: PiGovernanceDecision,
    toolName: string,
    logger?: PiGovernanceLogger
  ): { block: true; reason: string } {
    logger?.warn?.("Governance", "Blocked tool call", {
      toolName,
      reason: decision.reason,
      verdict: decision.verdict,
    });
    return {
      block: true,
      reason: decision.reason,
    };
  }

  private fromPolicyDecision(
    policyDecision: PolicyDecision,
    toolName: string
  ): PiGovernanceDecision {
    switch (policyDecision) {
      case "allow":
        return {
          verdict: "allow",
          reason: `Tool "${toolName}" allowed by policy`,
          matchedRule: toolName,
          source: "policy",
        };
      case "review":
        return {
          verdict: "review",
          reason: `Tool "${toolName}" requires approval by policy`,
          matchedRule: toolName,
          source: "policy",
        };
      case "deny":
      default:
        return {
          verdict: "deny",
          reason: `Tool "${toolName}" denied by policy`,
          matchedRule: toolName,
          source: "policy",
        };
    }
  }

  private evaluateBashSafety(input?: Record<string, unknown>): PiGovernanceDecision {
    const command = typeof input?.command === "string" ? input.command : "";

    for (const candidate of BASH_DENY_PATTERNS) {
      if (candidate.pattern.test(command)) {
        return {
          verdict: "deny",
          reason: `Blocked bash command: ${candidate.reason}`,
          matchedRule: candidate.pattern.source,
          source: "bash-safety",
        };
      }
    }

    for (const candidate of BASH_REVIEW_PATTERNS) {
      if (candidate.pattern.test(command)) {
        return {
          verdict: "review",
          reason: `Bash command requires approval: ${candidate.reason}`,
          matchedRule: candidate.pattern.source,
          source: "bash-safety",
        };
      }
    }

    return {
      verdict: "allow",
      reason: "Bash command allowed",
      source: "bash-safety",
    };
  }

  private record(
    kind: PiGovernanceAuditRecord["kind"],
    action: string,
    data: Omit<PiGovernanceAuditRecord, "kind" | "timestamp" | "action" | "auditEntry">
  ): void {
    const decision = data.decision?.verdict || "allow";
    const auditEntry = this.auditLogger.log({
      agentId: this.identity.did,
      action: `${kind}:${action}`,
      decision,
    });

    this.auditRecords.push({
      kind,
      timestamp: new Date().toISOString(),
      action,
      decision: data.decision,
      input: data.input,
      output: data.output,
      metadata: data.metadata,
      auditEntry,
    });
  }
}

function flattenContext(input?: Record<string, unknown>): Record<string, unknown> {
  if (!input) {
    return {};
  }

  const flattened: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      flattened[key] = value;
      continue;
    }
    flattened[key] = safeJson(value);
  }
  return flattened;
}

function summarizeToolResult(content: unknown): Record<string, unknown> {
  const serialized = safeJson(content);
  return {
    preview: serialized.slice(0, 1_000),
    size: serialized.length,
  };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
