// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, it, expect } from "vitest";
import { reviewCode, formatReviewResult } from "../src/reviewer";
import { validatePolicy, formatPolicyValidation } from "../src/policy-validator";
import { handleAgentRequest, parseYamlLite } from "../src/agent";
import { OWASP_AGENTIC_RISKS, getOwaspRisks, formatOwaspRisks, LEGACY_AT_TO_ASI } from "../src/owasp";

// ---------------------------------------------------------------------------
// reviewCode
// ---------------------------------------------------------------------------

describe("reviewCode", () => {
  it("passes clean governed code", () => {
    const source = `
      import { createGovernedTool, auditMiddleware } from "@agentmesh/mastra";
      const gov = governanceMiddleware({
        rateLimitPerMinute: 60,
        blockedPatterns: ["(?i)ignore previous"],
        piiFields: ["ssn"],
        allowedTools: ["search"],
      });
      const audit = auditMiddleware({ captureData: true });
    `;
    const result = reviewCode(source);
    expect(result.passed).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.summary).toContain("passed");
  });

  it("detects missing governance middleware in tool-bearing code", () => {
    const source = `
      async function execute(input) {
        return await myTool.execute(input);
      }
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "missing-governance-middleware")).toBe(true);
  });

  it("detects unguarded tool execution", () => {
    const source = `
      const result = await tool.execute({ query: userInput });
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "unguarded-tool-execution")).toBe(true);
  });

  it("detects missing audit logging in agent code", () => {
    const source = `
      class MyAgent extends Agent {
        async run() {
          return await this.tool.execute(this.input);
        }
      }
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "missing-audit-logging")).toBe(true);
  });

  it("detects missing PII redaction when handling user input", () => {
    const source = `
      const userInput = req.body.message;
      const response = await agent.execute({ input: userInput });
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "missing-pii-redaction")).toBe(true);
  });

  it("detects missing trust verification in multi-agent code", () => {
    const source = `
      async function handoff(subAgent, task) {
        return await subAgent.execute(task);
      }
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "missing-trust-verification")).toBe(true);
  });

  it("detects missing tool allow-list when governance is present", () => {
    const source = `
      const governed = createGovernedTool(myTool, {
        governance: { rateLimitPerMinute: 60 },
        audit: { captureData: true },
      });
      const audit = auditMiddleware({ captureData: true });
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "no-tool-allowlist")).toBe(true);
  });

  it("detects missing prompt-injection guards when governance is present", () => {
    const source = `
      const gov = governanceMiddleware({ allowedTools: ["search"], piiFields: ["ssn"] });
      const audit = auditMiddleware({ captureData: true });
    `;
    const result = reviewCode(source);
    expect(result.findings.some((f) => f.ruleId === "no-prompt-injection-guards")).toBe(true);
  });

  it("sets passed=false when high severity findings exist", () => {
    const source = `async function execute() { await tool.execute({}); }`;
    const result = reviewCode(source);
    expect(result.passed).toBe(false);
  });

  it("includes OWASP risk IDs in findings", () => {
    const source = `const result = await tool.execute({ query: input });`;
    const result = reviewCode(source);
    const allRisks = result.findings.flatMap((f) => f.owaspRisks);
    expect(allRisks.length).toBeGreaterThan(0);
  });

  it("formatReviewResult returns markdown string", () => {
    const source = `async function execute() { await tool.execute({}); }`;
    const result = reviewCode(source);
    const md = formatReviewResult(result);
    expect(typeof md).toBe("string");
    expect(md.length).toBeGreaterThan(0);
  });

  it("formatReviewResult contains install hint when findings exist", () => {
    const source = `async function execute() { await tool.execute({}); }`;
    const result = reviewCode(source);
    const md = formatReviewResult(result);
    expect(md).toContain("@agentmesh/mastra");
  });
});

// ---------------------------------------------------------------------------
// validatePolicy
// ---------------------------------------------------------------------------

describe("validatePolicy", () => {
  it("passes a complete valid policy", () => {
    const policy = {
      policy: {
        name: "test-policy",
        version: "1.0",
        rules: {
          rate_limit_per_minute: 60,
          pii_fields: ["ssn", "email"],
          blocked_patterns: ["ignore previous instructions"],
          allowed_tools: ["search"],
        },
        audit: { enabled: true, capture_data: false },
      },
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it("fails on null input", () => {
    const result = validatePolicy(null);
    expect(result.valid).toBe(false);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("fails when top-level `policy` key is missing", () => {
    const result = validatePolicy({ name: "oops" });
    expect(result.valid).toBe(false);
    expect(result.findings.some((f) => f.field === "policy")).toBe(true);
  });

  it("reports missing policy name", () => {
    const result = validatePolicy({ policy: { rules: {}, audit: { enabled: true } } });
    expect(result.findings.some((f) => f.field === "policy.name")).toBe(true);
  });

  it("reports missing rules section", () => {
    const result = validatePolicy({ policy: { name: "p", audit: { enabled: true } } });
    expect(result.findings.some((f) => f.field === "policy.rules")).toBe(true);
  });

  it("reports missing audit section", () => {
    const result = validatePolicy({ policy: { name: "p", rules: { rate_limit_per_minute: 30 } } });
    expect(result.findings.some((f) => f.field === "policy.audit")).toBe(true);
  });

  it("reports invalid rate_limit_per_minute", () => {
    const result = validatePolicy({
      policy: { name: "p", rules: { rate_limit_per_minute: -5 }, audit: { enabled: true } },
    });
    expect(result.findings.some((f) => f.field.includes("rate_limit_per_minute"))).toBe(true);
  });

  it("reports invalid regex in blocked_patterns", () => {
    const result = validatePolicy({
      policy: {
        name: "p",
        rules: { blocked_patterns: ["[invalid-regex"] },
        audit: { enabled: true },
      },
    });
    expect(result.findings.some((f) => f.field.includes("blocked_patterns"))).toBe(true);
  });

  it("reports empty rules object as warning", () => {
    const result = validatePolicy({
      policy: { name: "p", rules: {}, audit: { enabled: true } },
    });
    expect(result.findings.some((f) => f.field === "policy.rules")).toBe(true);
  });

  it("does not fail on valid rules with only allowed_tools", () => {
    const result = validatePolicy({
      policy: {
        name: "p",
        rules: { allowed_tools: ["search", "read"] },
        audit: { enabled: true },
      },
    });
    // Should not have rules-level error
    expect(result.findings.filter((f) => f.severity === "critical").length).toBe(0);
  });

  it("formatPolicyValidation returns markdown", () => {
    const result = validatePolicy(null);
    const md = formatPolicyValidation(result);
    expect(typeof md).toBe("string");
    expect(md).toContain("❌");
  });

  it("formatPolicyValidation is positive for a valid policy", () => {
    const result = validatePolicy({
      policy: {
        name: "p",
        version: "1.0",
        rules: { allowed_tools: ["search"] },
        audit: { enabled: true },
      },
    });
    const md = formatPolicyValidation(result);
    expect(md).toContain("✅");
  });
});

// ---------------------------------------------------------------------------
// OWASP helpers
// ---------------------------------------------------------------------------

describe("owasp", () => {
  it("exports OWASP_AGENTIC_RISKS with all ASI 2026 keys", () => {
    expect(OWASP_AGENTIC_RISKS["ASI01"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI02"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI03"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI04"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI05"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI06"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI07"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI08"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI09"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI10"]).toBeDefined();
    expect(OWASP_AGENTIC_RISKS["ASI11"]).toBeDefined();
  });

  it("getOwaspRisks returns matching risks for ASI IDs", () => {
    const risks = getOwaspRisks(["ASI01", "ASI08"]);
    expect(risks).toHaveLength(2);
    expect(risks[0].id).toBe("ASI01");
  });

  it("getOwaspRisks resolves legacy AT IDs via backward-compat mapping", () => {
    const risks = getOwaspRisks(["AT01", "AT08"]);
    expect(risks).toHaveLength(2);
    expect(risks[0].id).toBe("ASI01");
    expect(risks[1].id).toBe("ASI01"); // AT08 → ASI01
  });

  it("getOwaspRisks skips unknown IDs", () => {
    const risks = getOwaspRisks(["ASI01", "UNKNOWN"]);
    expect(risks).toHaveLength(1);
  });

  it("LEGACY_AT_TO_ASI maps all known AT IDs", () => {
    expect(LEGACY_AT_TO_ASI["AT01"]).toBe("ASI01");
    expect(LEGACY_AT_TO_ASI["AT06"]).toBe("ASI03");
    expect(LEGACY_AT_TO_ASI["AT09"]).toBe("ASI09");
  });

  it("formatOwaspRisks returns a non-empty string for valid ASI IDs", () => {
    const md = formatOwaspRisks(["ASI01", "ASI08"]);
    expect(md).toContain("ASI01");
    expect(md).toContain("ASI08");
    expect(md).toContain("https://");
  });

  it("formatOwaspRisks works with legacy AT IDs", () => {
    const md = formatOwaspRisks(["AT01", "AT08"]);
    expect(md).toContain("ASI01");
    expect(md).toContain("https://");
  });

  it("formatOwaspRisks returns empty string for empty array", () => {
    expect(formatOwaspRisks([])).toBe("");
  });
});

// ---------------------------------------------------------------------------
// parseYamlLite
// ---------------------------------------------------------------------------

describe("parseYamlLite", () => {
  it("parses a simple mapping", () => {
    const result = parseYamlLite("name: my-policy\nversion: '1.0'") as Record<string, unknown>;
    expect(result["name"]).toBe("my-policy");
    expect(result["version"]).toBe("1.0");
  });

  it("parses nested mappings", () => {
    const yaml = `
policy:
  name: test
  rules:
    rate_limit_per_minute: 60
    `;
    const result = parseYamlLite(yaml) as Record<string, unknown>;
    const policy = result["policy"] as Record<string, unknown>;
    expect(policy["name"]).toBe("test");
    const rules = policy["rules"] as Record<string, unknown>;
    expect(rules["rate_limit_per_minute"]).toBe(60);
  });

  it("parses block lists", () => {
    const yaml = `
pii_fields:
  - ssn
  - email
  - phone
    `;
    const result = parseYamlLite(yaml) as Record<string, unknown>;
    expect(result["pii_fields"]).toEqual(["ssn", "email", "phone"]);
  });

  it("parses inline lists", () => {
    const yaml = "tools: [search, read, write]";
    const result = parseYamlLite(yaml) as Record<string, unknown>;
    expect(result["tools"]).toEqual(["search", "read", "write"]);
  });

  it("parses boolean values", () => {
    const yaml = "enabled: true\ncapture_data: false";
    const result = parseYamlLite(yaml) as Record<string, unknown>;
    expect(result["enabled"]).toBe(true);
    expect(result["capture_data"]).toBe(false);
  });

  it("handles comments", () => {
    const yaml = "# A comment\nname: test # inline comment";
    const result = parseYamlLite(yaml) as Record<string, unknown>;
    expect(result["name"]).toBe("test # inline comment");
  });
});

// ---------------------------------------------------------------------------
// handleAgentRequest
// ---------------------------------------------------------------------------

describe("handleAgentRequest", () => {
  async function collect(gen: AsyncGenerator<{ content: string }>): Promise<string> {
    let out = "";
    for await (const token of gen) {
      out += token.content;
    }
    return out;
  }

  it("returns help text for unknown message", async () => {
    const output = await collect(
      handleAgentRequest({ messages: [{ role: "user", content: "what can you do?" }] })
    );
    expect(output).toContain("Governance");
    expect(output).toContain("review");
  });

  it("reviews a code block", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [
          {
            role: "user",
            content:
              "@governance review\n```ts\nconst r = await tool.execute({ q: input });\n```",
          },
        ],
      })
    );
    expect(output.length).toBeGreaterThan(0);
    // Should either pass or report findings
    expect(output.includes("passed") || output.includes("issue")).toBe(true);
  });

  it("validates a YAML policy block", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [
          {
            role: "user",
            content:
              "@governance validate\n```yaml\npolicy:\n  name: test\n  rules:\n    rate_limit_per_minute: 30\n  audit:\n    enabled: true\n```",
          },
        ],
      })
    );
    expect(output.length).toBeGreaterThan(0);
    expect(output.includes("✅") || output.includes("❌") || output.includes("⚠️")).toBe(true);
  });

  it("warns when validate is used without a code block", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [{ role: "user", content: "@governance validate" }],
      })
    );
    expect(output).toContain("No YAML block");
  });

  it("returns OWASP summary for owasp command", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [{ role: "user", content: "@governance owasp" }],
      })
    );
    expect(output).toContain("ASI01");
    expect(output).toContain("ASI08");
  });

  it("uses help fallback for explicit help command", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [{ role: "user", content: "@governance help" }],
      })
    );
    expect(output).toContain("review");
    expect(output).toContain("validate");
  });

  it("defaults to review when a code block is present without a command", async () => {
    const output = await collect(
      handleAgentRequest({
        messages: [
          {
            role: "user",
            content: "What does this do?\n```ts\nawait tool.execute({});\n```",
          },
        ],
      })
    );
    // Should give a review-style response
    expect(output.length).toBeGreaterThan(0);
  });

  it("handles empty messages array gracefully", async () => {
    const output = await collect(handleAgentRequest({ messages: [] }));
    expect(output.length).toBeGreaterThan(0);
  });
});
