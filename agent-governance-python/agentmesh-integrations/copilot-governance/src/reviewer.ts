// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Static code reviewer for agent governance gaps.
 *
 * Analyses source code (Python or TypeScript/JavaScript) for:
 * - Missing governance middleware wrapping
 * - Unguarded tool calls (direct .execute() without policy check)
 * - Missing audit logging
 * - Absence of PII redaction
 * - Unconstrained tool allow-lists
 * - Stub security implementations (verify/validate always returning True)
 * - Hardcoded security deny-lists discoverable by attackers
 * - Unsafe deserialization (pickle without HMAC)
 * - Unbounded collection growth (memory DoS)
 * - Missing circuit breakers on external calls
 * - SSRF-vulnerable URL handling
 * - Missing agent behavior monitoring
 *
 * Each finding is mapped to relevant OWASP Agentic Security Initiative Top 10 (ASI 2026) risk IDs.
 *
 * Rules 8–14 are based on patterns discovered during external security
 * researcher reports and subsequent codebase-wide audits.
 */

import type { ReviewFinding, ReviewResult, Severity } from "./types";

/** A review rule with its detector logic. */
interface Rule {
  ruleId: string;
  title: string;
  severity: Severity;
  owaspRisks: string[];
  /** Returns a finding (with optional line) if the rule fires, or null. */
  detect(source: string): Omit<ReviewFinding, "ruleId" | "title" | "severity" | "owaspRisks"> | null;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const RULES: Rule[] = [
  // ── 1. Governance middleware missing ──────────────────────────────────────
  {
    ruleId: "missing-governance-middleware",
    title: "No governance middleware detected",
    severity: "high",
    owaspRisks: ["ASI02", "ASI01"],
    detect(source) {
      const hasGovernance =
        /governanceMiddleware|governance_middleware|GovernancePolicy|apply_governance/i.test(source);
      if (hasGovernance) return null;
      // Only flag if there are tool definitions — not every file needs governance
      const hasTools =
        /createTool|BaseTool|Tool\b|@tool|def\s+\w+.*tool/i.test(source) ||
        /execute\s*[:(]|\.execute\(/i.test(source);
      if (!hasTools) return null;
      return {
        description:
          "This file defines or executes agent tools but does not apply governance middleware. " +
          "Without policy enforcement, tools can be invoked without rate-limiting, " +
          "content filtering, or allow/deny-list checks.",
        suggestion:
          "Wrap your tool with `governanceMiddleware` (TS) or `apply_governance` (Python):\n\n" +
          "```ts\nimport { createGovernedTool } from '@agentmesh/mastra';\n" +
          "const safe = createGovernedTool(myTool, {\n" +
          "  governance: { rateLimitPerMinute: 60, blockedPatterns: ['(?i)ignore previous'] },\n" +
          "});\n```",
      };
    },
  },

  // ── 2. Unguarded direct tool execution ────────────────────────────────────
  {
    ruleId: "unguarded-tool-execution",
    title: "Direct tool execution without policy check",
    severity: "high",
    owaspRisks: ["ASI02", "ASI01"],
    detect(source) {
      // Look for .execute( calls not preceded by a governance/policy check
      const hasDirectExecute = /\.execute\s*\(/.test(source);
      if (!hasDirectExecute) return null;
      const hasGovernanceCheck =
        /\.check\s*\(|governanceMiddleware|createGovernedTool|governance_check|policy\.check/i.test(
          source
        );
      if (hasGovernanceCheck) return null;
      return {
        description:
          "Tool `.execute()` is called directly without a preceding governance policy check. " +
          "This bypasses content filtering, rate limiting, and tool allow-list enforcement.",
        suggestion:
          "Use `createGovernedTool` to wrap the tool, or call `gov.check()` before executing:\n\n" +
          "```ts\nconst result = await gov.check(input, toolId, agentId);\nif (!result.allowed) throw new Error(result.reason);\n```",
      };
    },
  },

  // ── 3. Missing audit logging ───────────────────────────────────────────────
  {
    ruleId: "missing-audit-logging",
    title: "No audit logging detected",
    severity: "high",
    owaspRisks: ["ASI09", "ASI11"],
    detect(source) {
      const hasAudit =
        /auditMiddleware|audit_middleware|audit\.record|AuditLog|audit_log|hash_chain/i.test(
          source
        );
      if (hasAudit) return null;
      const hasAgentOrTool =
        /Agent|createTool|BaseTool|\.execute\(/i.test(source);
      if (!hasAgentOrTool) return null;
      return {
        description:
          "No audit logging was found. Without a tamper-evident audit trail, " +
          "tool invocations cannot be reviewed after the fact, which undermines " +
          "accountability and incident response.",
        suggestion:
          "Add audit logging with a hash-chain to detect tampering:\n\n" +
          "```ts\nimport { auditMiddleware } from '@agentmesh/mastra';\n" +
          "const audit = auditMiddleware({ captureData: true });\n" +
          "await audit.record({ toolId, agentId, action: 'invoke', input });\n```",
      };
    },
  },

  // ── 4. No PII redaction ────────────────────────────────────────────────────
  {
    ruleId: "missing-pii-redaction",
    title: "No PII redaction configured",
    severity: "medium",
    owaspRisks: ["ASI03"],
    detect(source) {
      const hasPii =
        /piiFields|pii_fields|redact_pii|REDACTED|pii_redact/i.test(source);
      if (hasPii) return null;
      // Only flag if agent handles user input
      const handlesInput =
        /user_input|userInput|input\s*[:=]|message\s*[:=]/i.test(source);
      if (!handlesInput) return null;
      return {
        description:
          "The agent handles user input but no PII redaction is configured. " +
          "Sensitive fields (SSN, email, credit-card numbers) may be logged or " +
          "forwarded to downstream services in plaintext.",
        suggestion:
          "Configure `piiFields` in your governance policy:\n\n" +
          "```ts\ngovernanceMiddleware({\n  piiFields: ['ssn', 'email', 'credit_card', 'password'],\n});\n```",
      };
    },
  },

  // ── 5. No trust verification ───────────────────────────────────────────────
  {
    ruleId: "missing-trust-verification",
    title: "No trust score verification for agent-to-agent calls",
    severity: "medium",
    owaspRisks: ["ASI07", "ASI03"],
    detect(source) {
      const hasTrust =
        /trustGate|trust_gate|TrustConfig|minTrustScore|min_trust_score|getTrustScore/i.test(
          source
        );
      if (hasTrust) return null;
      // Only flag if multi-agent patterns exist
      const hasMultiAgent =
        /handoff|delegate|sub.?agent|agent.?call|invoke.*agent/i.test(source);
      if (!hasMultiAgent) return null;
      return {
        description:
          "Agent handoffs or sub-agent invocations were found but no trust score " +
          "verification is applied. A compromised sub-agent could perform actions " +
          "beyond its intended scope.",
        suggestion:
          "Add a trust gate before delegating to sub-agents:\n\n" +
          "```ts\nimport { trustGate } from '@agentmesh/mastra';\n" +
          "const gate = trustGate({ minTrustScore: 500, getTrustScore: fetchScore });\n" +
          "const result = await gate.verify(subAgentId);\n" +
          "if (!result.verified) throw new Error('Untrusted agent');\n```",
      };
    },
  },

  // ── 6. Unconstrained tool allow-list ──────────────────────────────────────
  {
    ruleId: "no-tool-allowlist",
    title: "No tool allow-list or deny-list configured",
    severity: "medium",
    owaspRisks: ["ASI01", "ASI02"],
    detect(source) {
      const hasAllowlist =
        /allowedTools|allowed_tools|blockedTools|blocked_tools|tool_allowlist|tool_denylist/i.test(
          source
        );
      if (hasAllowlist) return null;
      const hasGovernance =
        /governanceMiddleware|createGovernedTool|governance_middleware/i.test(source);
      if (!hasGovernance) return null; // already caught by rule 1
      return {
        description:
          "Governance middleware is present but no tool allow-list or deny-list is defined. " +
          "Without explicit tool constraints, any tool ID is accepted, which enables " +
          "excessive-agency attacks if the LLM generates an unexpected tool name.",
        suggestion:
          "Define an explicit tool allow-list:\n\n" +
          "```ts\ngovernanceMiddleware({\n" +
          "  allowedTools: ['web-search', 'read-file'],  // only these\n" +
          "  blockedTools: ['shell-exec', 'file-delete'], // never these\n" +
          "});\n```",
      };
    },
  },

  // ── 7. Prompt-injection patterns ──────────────────────────────────────────
  {
    ruleId: "no-prompt-injection-guards",
    title: "No prompt-injection input filters configured",
    severity: "medium",
    owaspRisks: ["ASI01"],
    detect(source) {
      const hasPatterns =
        /blockedPatterns|blocked_patterns|prompt.?injection|content.?filter/i.test(source);
      if (hasPatterns) return null;
      const hasGovernance =
        /governanceMiddleware|createGovernedTool|governance_middleware/i.test(source);
      if (!hasGovernance) return null;
      return {
        description:
          "Governance middleware is present but `blockedPatterns` is not set. " +
          "Without content filtering, prompt-injection strings such as " +
          '"ignore previous instructions" can reach the agent.',
        suggestion:
          "Add prompt-injection guards to your policy:\n\n" +
          "```ts\ngovernanceMiddleware({\n" +
          "  blockedPatterns: [\n" +
          "    'ignore (all )?previous instructions',  // i flag applied automatically\n" +
          "    'system prompt',\n" +
          "    'act as (if you are|a)',\n" +
          "  ],\n" +
          "});\n```",
      };
    },
  },

  // ── 8. Stub security implementations ────────────────────────────────────
  // MSRC learning: Fabricated DIDs passed trust handshake because verify()
  // was a stub that always returned True.
  {
    ruleId: "stub-security-implementation",
    title: "Security function appears to be a stub (always returns True/success)",
    severity: "critical",
    owaspRisks: ["ASI02", "ASI03"],
    detect(source) {
      // Python: def verify/validate/authenticate that just returns True
      const stubPattern =
        /def\s+(verify|validate|authenticate|check_permission|is_authorized|is_trusted)[^}]*:\s*\n\s*return\s+True/;
      if (!stubPattern.test(source)) return null;
      return {
        description:
          "A security-critical function (verify/validate/authenticate) appears to " +
          "unconditionally return True without performing actual checks. " +
          "This allows any caller to bypass the security boundary. " +
          "This pattern was the root cause of a real-world vulnerability where " +
          "fabricated agent identities passed trust handshakes.",
        suggestion:
          "Implement actual verification logic:\n\n" +
          "```python\nasync def verify_peer(self, peer_did: str) -> bool:\n" +
          "    peer = self.registry.get(peer_did)\n" +
          "    if not peer or not peer.is_active():\n" +
          "        return False\n" +
          "    # Cryptographic challenge-response\n" +
          "    challenge = self.create_challenge()\n" +
          "    response = await peer.respond(challenge)\n" +
          "    return self._verify_signature(response, peer.public_key)\n```",
      };
    },
  },

  // ── 9. Hardcoded security deny-lists ───────────────────────────────────
  // MSRC learning: Hardcoded patterns in source are discoverable by
  // attackers, enabling targeted bypass.
  {
    ruleId: "hardcoded-security-denylist",
    title: "Hardcoded security deny-list found in source code",
    severity: "high",
    owaspRisks: ["ASI01", "ASI04"],
    detect(source) {
      // Look for inline lists of SQL keywords, dangerous commands, PII patterns
      const hardcodedLists =
        /(?:dangerous_patterns|blocked_patterns|destructive_patterns|sensitive_keywords)\s*=\s*\[/;
      const hardcodedRegexList =
        /(?:HARM_PATTERNS|ILLEGAL_PATTERNS|MALWARE_PATTERNS|BLOCKED_)\s*=\s*\[/;
      if (!hardcodedLists.test(source) && !hardcodedRegexList.test(source)) return null;
      return {
        description:
          "Security deny-list patterns are hardcoded in source code. " +
          "Attackers with read access can reverse-engineer exactly which patterns " +
          "are blocked and craft bypasses. This is a known finding pattern " +
          "reported by external security researchers.",
        suggestion:
          "Externalize security rules into a YAML config loaded at runtime:\n\n" +
          "```python\nfrom my_module import load_policy_config, PolicyConfig\n\n" +
          "config = load_policy_config('/secure/path/rules.yaml')\n" +
          "engine = PolicyEngine(config=config)\n```\n\n" +
          "Keep built-in defaults in a config dataclass but warn when they are used.",
      };
    },
  },

  // ── 10. Unsafe deserialization (pickle without HMAC) ──────────────────
  // MSRC learning: pickle.loads without integrity check enables code execution
  {
    ruleId: "unsafe-deserialization",
    title: "pickle.loads() called without integrity verification",
    severity: "critical",
    owaspRisks: ["ASI05", "ASI02"],
    detect(source) {
      const hasPickleLoad = /pickle\.loads?\s*\(/.test(source);
      if (!hasPickleLoad) return null;
      const hasHmacCheck = /hmac\.(new|compare_digest)|verify.*signature|verify.*integrity/i.test(source);
      if (hasHmacCheck) return null;
      return {
        description:
          "pickle.loads() is called without HMAC or signature verification. " +
          "An attacker who can tamper with the serialized data can achieve " +
          "arbitrary code execution via crafted pickle payloads.",
        suggestion:
          "Sign serialized data with HMAC-SHA256 and verify before deserializing:\n\n" +
          "```python\nimport hmac, hashlib, pickle\n\n" +
          "# Save\ndata = pickle.dumps(obj)\n" +
          "sig = hmac.new(key, data, hashlib.sha256).hexdigest()\n\n" +
          "# Load\nif not hmac.compare_digest(hmac.new(key, data, hashlib.sha256).hexdigest(), sig):\n" +
          "    raise ValueError('Integrity check failed')\nobj = pickle.loads(data)\n```",
      };
    },
  },

  // ── 11. Unbounded collection growth ───────────────────────────────────
  // MSRC learning: Dict/list without size limits → memory DoS
  {
    ruleId: "unbounded-collection",
    title: "Security-sensitive collection has no size limit",
    severity: "medium",
    owaspRisks: ["ASI08"],
    detect(source) {
      // Look for dicts/lists used for caching, rate-limiting, session tracking
      // that grow without eviction
      const hasCacheDict =
        /(?:_cache|_sessions|_pending|_peers|_clients|_buckets|_tokens)\s*[=:]\s*(?:\{\}|dict\(\)|defaultdict)/;
      if (!hasCacheDict.test(source)) return null;
      const hasEviction =
        /\.pop\(|\.popitem\(|max_size|maxsize|_MAX_|_evict|_cleanup|LRUCache|lru_cache|OrderedDict/i.test(
          source
        );
      if (hasEviction) return null;
      return {
        description:
          "A dictionary or collection used for caching/session tracking grows " +
          "without a size limit or eviction strategy. An attacker can exhaust " +
          "memory by creating many unique keys (e.g., fake agent DIDs, session IDs).",
        suggestion:
          "Add a maximum size and eviction policy:\n\n" +
          "```python\nif len(self._cache) >= self._MAX_ENTRIES:\n" +
          "    oldest = min(self._cache, key=lambda k: self._cache[k].last_used)\n" +
          "    del self._cache[oldest]\n```",
      };
    },
  },

  // ── 12. Missing circuit breaker on external calls ─────────────────────
  // MSRC learning: No backoff on failing tool calls → cascade failure
  {
    ruleId: "missing-circuit-breaker",
    title: "External service calls lack circuit breaker pattern",
    severity: "medium",
    owaspRisks: ["ASI08", "ASI10"],
    detect(source) {
      const hasExternalCall =
        /httpx\.|aiohttp\.|requests\.|fetch\(|urllib|invoke_tool|call_tool/i.test(source);
      if (!hasExternalCall) return null;
      const hasCircuitBreaker =
        /circuit.?breaker|CircuitBreaker|_failures.*threshold|backoff|retry.*max|tenacity/i.test(
          source
        );
      if (hasCircuitBreaker) return null;
      return {
        description:
          "External service calls (HTTP, tool invocations) have no circuit breaker. " +
          "If a downstream service fails, the agent will retry indefinitely, causing " +
          "cascading failures and resource exhaustion.",
        suggestion:
          "Add a circuit breaker that opens after N consecutive failures:\n\n" +
          "```python\nif self._consecutive_failures >= self._threshold:\n" +
          "    raise CircuitBreakerOpen(f'{tool_name} circuit open')\n" +
          "try:\n    result = await call_external()\n" +
          "    self._consecutive_failures = 0\n" +
          "except Exception:\n    self._consecutive_failures += 1\n    raise\n```",
      };
    },
  },

  // ── 13. SSRF-vulnerable URL handling ──────────────────────────────────
  // MSRC learning: MCP server_url not validated → SSRF to metadata endpoint
  {
    ruleId: "ssrf-vulnerable-url",
    title: "URL from untrusted input used without SSRF guard",
    severity: "high",
    owaspRisks: ["ASI02", "ASI05"],
    detect(source) {
      const hasUrlFromInput =
        /(?:server_url|endpoint|url|base_url)\s*[:=].*(?:args|params|request|input|config)/i.test(
          source
        );
      if (!hasUrlFromInput) return null;
      const hasSsrfGuard =
        /(?:localhost|127\.0\.0\.1|169\.254|::1|0\.0\.0\.0).*block|ssrf|_BLOCKED_HOSTS|validate_url|_is_safe_url/i.test(
          source
        );
      if (hasSsrfGuard) return null;
      return {
        description:
          "A URL derived from user/agent input is used for HTTP requests without " +
          "SSRF validation. An attacker can point the URL to internal services " +
          "(169.254.169.254 metadata endpoint, localhost admin panels).",
        suggestion:
          "Block internal/reserved addresses before making requests:\n\n" +
          "```python\nBLOCKED = {'localhost', '127.0.0.1', '::1', '0.0.0.0', '169.254.169.254'}\n" +
          "parsed = urllib.parse.urlparse(url)\n" +
          "if parsed.hostname in BLOCKED:\n" +
          "    raise ValueError('SSRF: blocked host')\n```",
      };
    },
  },

  // ── 14. Missing agent behavior monitoring ─────────────────────────────
  // MSRC learning: No runtime anomaly detection → rogue agents undetected
  {
    ruleId: "no-behavior-monitoring",
    title: "No agent behavior monitoring or anomaly detection",
    severity: "medium",
    owaspRisks: ["ASI10", "ASI11"],
    detect(source) {
      const hasMonitor =
        /BehaviorMonitor|behavior_monitor|anomaly_detect|RogueDetect|quarantine|AgentMetrics/i.test(
          source
        );
      if (hasMonitor) return null;
      // Only flag if this is an agent orchestrator
      const hasOrchestration =
        /orchestrat|multi.?agent.?(?:system|pool|run)|agent.?pool|spawn.*agent|register.*agent/i.test(
          source
        );
      if (!hasOrchestration) return null;
      return {
        description:
          "Multi-agent orchestration code has no behavior monitoring. " +
          "Without anomaly detection, a rogue agent can make excessive tool calls, " +
          "escalate privileges, or exfiltrate data without triggering alerts.",
        suggestion:
          "Add the AgentBehaviorMonitor to track per-agent metrics:\n\n" +
          "```python\nfrom agentmesh.services.behavior_monitor import AgentBehaviorMonitor\n\n" +
          "monitor = AgentBehaviorMonitor(burst_threshold=100, consecutive_failure_threshold=20)\n" +
          "monitor.record_tool_call(agent_did, tool_name, success=True)\n" +
          "if monitor.is_quarantined(agent_did):\n    raise PermissionError('Agent quarantined')\n```",
      };
    },
  },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Review agent source code for governance gaps.
 *
 * @param source - Raw source code string (Python or TypeScript/JavaScript).
 * @returns A ReviewResult with all findings and a summary.
 *
 * @example
 * ```ts
 * import { reviewCode } from '@agentmesh/copilot-governance';
 *
 * const result = reviewCode(myAgentSource);
 * if (!result.passed) {
 *   console.log(result.summary);
 * }
 * ```
 */
export function reviewCode(source: string): ReviewResult {
  const findings: ReviewFinding[] = [];

  for (const rule of RULES) {
    const match = rule.detect(source);
    if (match) {
      findings.push({
        ruleId: rule.ruleId,
        title: rule.title,
        severity: rule.severity,
        owaspRisks: rule.owaspRisks,
        ...match,
      });
    }
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const passed = critical === 0 && high === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = "✅ **Governance review passed.** No issues found.";
  } else {
    const parts: string[] = [];
    if (critical) parts.push(`${critical} critical`);
    if (high) parts.push(`${high} high`);
    if (medium) parts.push(`${medium} medium`);
    summary =
      `${passed ? "⚠️" : "❌"} **Governance review found ${findings.length} issue(s)**: ` +
      parts.join(", ") +
      ".";
  }

  return { findings, passed, summary };
}

/**
 * Format a ReviewResult as a Markdown string suitable for a Copilot chat reply.
 */
export function formatReviewResult(result: ReviewResult): string {
  const lines: string[] = [result.summary, ""];

  if (result.findings.length === 0) {
    lines.push(
      "Your agent code follows the governance baseline. " +
        "Consider also running `policy-validate` on your YAML policy files."
    );
    return lines.join("\n");
  }

  for (const finding of result.findings) {
    const badge = severityBadge(finding.severity);
    lines.push(`### ${badge} ${finding.title}`);
    lines.push(`**Rule:** \`${finding.ruleId}\``);
    lines.push("");
    lines.push(finding.description);
    if (finding.suggestion) {
      lines.push("");
      lines.push("**Suggested fix:**");
      lines.push(finding.suggestion);
    }
    if (finding.owaspRisks.length > 0) {
      lines.push("");
      lines.push(
        `**OWASP Agentic Top-10:** ${finding.owaspRisks.map((id) => `\`${id}\``).join(", ")}`
      );
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  lines.push(
    "> 📦 Add governance to your agent in minutes: " +
      "`npm install @agentmesh/mastra` (TypeScript) or " +
      "`pip install agent-os-kernel` (Python)."
  );

  return lines.join("\n");
}

function severityBadge(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}
