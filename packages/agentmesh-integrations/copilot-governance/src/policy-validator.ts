// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Validator for agent governance policy YAML files.
 *
 * Validates that a parsed policy object has the required structure and
 * sane values. Does NOT depend on a YAML parser — callers parse YAML
 * themselves and pass the resulting plain object.
 *
 * Supported policy schemas
 * ─────────────────────────
 * The validator understands the canonical AgentMesh policy shape:
 *
 * ```yaml
 * policy:
 *   name: my-agent-policy
 *   version: "1.0"
 *   rules:
 *     rate_limit_per_minute: 60
 *     max_input_length: 10000
 *     pii_fields: [ssn, email]
 *     blocked_patterns:
 *       - "(?i)ignore previous"
 *     allowed_tools: [web-search, read-file]
 *     blocked_tools: [shell-exec]
 *   audit:
 *     enabled: true
 *     capture_data: false
 * ```
 */

import type { PolicyFinding, PolicyValidationResult } from "./types";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function addFinding(
  findings: PolicyFinding[],
  field: string,
  message: string,
  severity: PolicyFinding["severity"]
): void {
  findings.push({ field, message, severity });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a parsed governance policy object.
 *
 * @param rawPolicy - The plain JS object produced by parsing a YAML file.
 * @returns A PolicyValidationResult with findings and a summary.
 *
 * @example
 * ```ts
 * import { validatePolicy } from '@agentmesh/copilot-governance';
 * import { parse } from 'yaml'; // any YAML parser
 *
 * const result = validatePolicy(parse(yamlText));
 * if (!result.valid) {
 *   console.log(result.summary);
 * }
 * ```
 */
export function validatePolicy(rawPolicy: unknown): PolicyValidationResult {
  const findings: PolicyFinding[] = [];

  if (rawPolicy === null || rawPolicy === undefined) {
    addFinding(findings, "<root>", "Policy is empty or null.", "critical");
    return { valid: false, findings, summary: "❌ Policy file is empty." };
  }

  if (typeof rawPolicy !== "object" || Array.isArray(rawPolicy)) {
    addFinding(
      findings,
      "<root>",
      "Policy must be an object (YAML mapping), not an array or scalar.",
      "critical"
    );
    return { valid: false, findings, summary: "❌ Policy root must be an object." };
  }

  const root = rawPolicy as Record<string, unknown>;

  // ── Top-level `policy` key ───────────────────────────────────────────────
  if (!("policy" in root)) {
    addFinding(
      findings,
      "policy",
      "Missing top-level `policy` key. The file must begin with `policy:`.",
      "critical"
    );
    return { valid: false, findings, summary: "❌ Missing required `policy` key." };
  }

  const policy = root["policy"];
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    addFinding(findings, "policy", "`policy` must be an object, not a scalar or array.", "critical");
    return { valid: false, findings, summary: "❌ `policy` must be an object." };
  }

  const p = policy as Record<string, unknown>;

  // ── Required metadata ────────────────────────────────────────────────────
  if (!p["name"] || typeof p["name"] !== "string" || p["name"].trim() === "") {
    addFinding(findings, "policy.name", "`policy.name` is required and must be a non-empty string.", "high");
  }

  if (!p["version"]) {
    addFinding(findings, "policy.version", "`policy.version` is recommended (e.g. \"1.0\").", "low");
  }

  // ── Rules section ────────────────────────────────────────────────────────
  if (!("rules" in p)) {
    addFinding(
      findings,
      "policy.rules",
      "`policy.rules` section is missing. Without rules the policy enforces nothing.",
      "high"
    );
  } else {
    const rules = p["rules"];
    if (typeof rules !== "object" || rules === null || Array.isArray(rules)) {
      addFinding(findings, "policy.rules", "`policy.rules` must be an object.", "high");
    } else {
      const r = rules as Record<string, unknown>;

      // rate_limit_per_minute
      if ("rate_limit_per_minute" in r) {
        const rl = r["rate_limit_per_minute"];
        if (typeof rl !== "number" || !Number.isInteger(rl) || rl <= 0) {
          addFinding(
            findings,
            "policy.rules.rate_limit_per_minute",
            "`rate_limit_per_minute` must be a positive integer.",
            "medium"
          );
        }
      }

      // max_input_length
      if ("max_input_length" in r) {
        const mil = r["max_input_length"];
        if (typeof mil !== "number" || !Number.isInteger(mil) || mil <= 0) {
          addFinding(
            findings,
            "policy.rules.max_input_length",
            "`max_input_length` must be a positive integer.",
            "medium"
          );
        }
      }

      // pii_fields
      if ("pii_fields" in r) {
        const pii = r["pii_fields"];
        if (!Array.isArray(pii)) {
          addFinding(
            findings,
            "policy.rules.pii_fields",
            "`pii_fields` must be a list of strings.",
            "medium"
          );
        } else {
          for (let i = 0; i < pii.length; i++) {
            if (typeof pii[i] !== "string" || (pii[i] as string).trim() === "") {
              addFinding(
                findings,
                `policy.rules.pii_fields[${i}]`,
                "Each PII field name must be a non-empty string.",
                "medium"
              );
            }
          }
        }
      }

      // blocked_patterns
      if ("blocked_patterns" in r) {
        const bp = r["blocked_patterns"];
        if (!Array.isArray(bp)) {
          addFinding(
            findings,
            "policy.rules.blocked_patterns",
            "`blocked_patterns` must be a list of regex strings.",
            "medium"
          );
        } else {
          for (let i = 0; i < bp.length; i++) {
            if (typeof bp[i] !== "string" || (bp[i] as string).trim() === "") {
              addFinding(
                findings,
                `policy.rules.blocked_patterns[${i}]`,
                "Each blocked pattern must be a non-empty string (regex).",
                "medium"
              );
            } else {
              // Validate that the regex compiles
              try {
                new RegExp(bp[i] as string);
              } catch {
                addFinding(
                  findings,
                  `policy.rules.blocked_patterns[${i}]`,
                  `Pattern "${bp[i]}" is not a valid regular expression.`,
                  "high"
                );
              }
            }
          }
        }
      }

      // allowed_tools / blocked_tools
      for (const listKey of ["allowed_tools", "blocked_tools"] as const) {
        if (listKey in r) {
          const tools = r[listKey];
          if (!Array.isArray(tools)) {
            addFinding(
              findings,
              `policy.rules.${listKey}`,
              `\`${listKey}\` must be a list of strings.`,
              "medium"
            );
          } else {
            for (let i = 0; i < tools.length; i++) {
              if (typeof tools[i] !== "string" || (tools[i] as string).trim() === "") {
                addFinding(
                  findings,
                  `policy.rules.${listKey}[${i}]`,
                  "Each tool name must be a non-empty string.",
                  "medium"
                );
              }
            }
          }
        }
      }

      // Warn if no enforcement rules are set
      const enforcementKeys = [
        "rate_limit_per_minute",
        "max_input_length",
        "blocked_patterns",
        "allowed_tools",
        "blocked_tools",
        "pii_fields",
      ];
      const hasAnyRule = enforcementKeys.some((k) => k in r);
      if (!hasAnyRule) {
        addFinding(
          findings,
          "policy.rules",
          "No enforcement rules are defined. Consider adding at least one of: " +
            enforcementKeys.join(", ") +
            ".",
          "medium"
        );
      }
    }
  }

  // ── Audit section ────────────────────────────────────────────────────────
  if (!("audit" in p)) {
    addFinding(
      findings,
      "policy.audit",
      "`policy.audit` section is missing. Audit logging is strongly recommended.",
      "medium"
    );
  } else {
    const audit = p["audit"];
    if (typeof audit !== "object" || audit === null || Array.isArray(audit)) {
      addFinding(findings, "policy.audit", "`policy.audit` must be an object.", "medium");
    } else {
      const a = audit as Record<string, unknown>;
      if ("enabled" in a && typeof a["enabled"] !== "boolean") {
        addFinding(findings, "policy.audit.enabled", "`audit.enabled` must be a boolean.", "low");
      }
      if ("capture_data" in a && typeof a["capture_data"] !== "boolean") {
        addFinding(
          findings,
          "policy.audit.capture_data",
          "`audit.capture_data` must be a boolean.",
          "low"
        );
      }
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  const errors = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const valid = errors.length === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = "✅ **Policy validation passed.** The policy file is well-formed.";
  } else {
    const errorCount = errors.length;
    const warnCount = findings.length - errorCount;
    const parts: string[] = [];
    if (errorCount) parts.push(`${errorCount} error(s)`);
    if (warnCount) parts.push(`${warnCount} warning(s)`);
    summary =
      (valid ? "⚠️" : "❌") +
      ` **Policy validation found ${findings.length} issue(s)**: ` +
      parts.join(", ") +
      ".";
  }

  return { valid, findings, summary };
}

/**
 * Format a PolicyValidationResult as a Markdown string suitable for a Copilot reply.
 */
export function formatPolicyValidation(result: PolicyValidationResult): string {
  const lines: string[] = [result.summary, ""];

  if (result.findings.length === 0) {
    lines.push("Your policy YAML is valid and complete. 🎉");
    return lines.join("\n");
  }

  for (const finding of result.findings) {
    const icon =
      finding.severity === "critical" || finding.severity === "high"
        ? "❌"
        : finding.severity === "medium"
          ? "⚠️"
          : "ℹ️";
    lines.push(`- ${icon} **\`${finding.field}\`** — ${finding.message}`);
  }

  lines.push("");
  lines.push(
    "> See the [AgentMesh Policy Reference](https://github.com/microsoft/agent-governance-toolkit) " +
      "for a complete policy YAML schema."
  );

  return lines.join("\n");
}
