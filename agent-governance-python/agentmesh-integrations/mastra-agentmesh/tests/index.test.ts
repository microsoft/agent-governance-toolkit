// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { describe, it, expect, beforeEach } from "vitest";
import {
  AgentControlBlockedError,
  InterventionPoint,
  type AgentControl,
  type InterventionPointResult,
} from "agent-control-specification";
import { trustGate } from "../src/trust";
import { auditMiddleware, type AuditEntry } from "../src/audit";
import { createGovernedTool } from "../src/governed-tool";

describe("trustGate", () => {
  it("allows agents above threshold", async () => {
    const gate = trustGate({
      minTrustScore: 500,
      getTrustScore: async () => 750,
    });
    const result = await gate.verify("agent-1");
    expect(result.verified).toBe(true);
    expect(result.trustScore).toBe(750);
  });

  it("blocks agents below threshold", async () => {
    const gate = trustGate({
      minTrustScore: 700,
      getTrustScore: async () => 400,
    });
    const result = await gate.verify("agent-1");
    expect(result.verified).toBe(false);
    expect(result.trustScore).toBe(400);
  });

  it("calls onTrustFailure when blocked", async () => {
    let failedAgent = "";
    const gate = trustGate({
      minTrustScore: 500,
      getTrustScore: async () => 100,
      onTrustFailure: async (id) => {
        failedAgent = id;
      },
    });
    await gate.verify("bad-agent");
    expect(failedAgent).toBe("bad-agent");
  });

  it("returns correct trust tiers", () => {
    const gate = trustGate({
      minTrustScore: 0,
      getTrustScore: async () => 0,
    });
    expect(gate.getTier(950)).toBe("verified_partner");
    expect(gate.getTier(750)).toBe("trusted");
    expect(gate.getTier(600)).toBe("standard");
    expect(gate.getTier(350)).toBe("probationary");
    expect(gate.getTier(100)).toBe("untrusted");
  });
});

describe("auditMiddleware", () => {
  let audit: ReturnType<typeof auditMiddleware>;

  beforeEach(() => {
    audit = auditMiddleware({ captureData: true, maxEntries: 100 });
    audit.clear();
  });

  it("records audit entries", async () => {
    const entry = await audit.record({
      toolId: "search",
      agentId: "agent-1",
      action: "invoke",
      input: { query: "test" },
    });
    expect(entry.toolId).toBe("search");
    expect(entry.action).toBe("invoke");
    expect(entry.hash).toHaveLength(64);
  });

  it("maintains hash chain integrity", async () => {
    await audit.record({ toolId: "t1", agentId: "a", action: "invoke" });
    await audit.record({ toolId: "t2", agentId: "a", action: "complete" });
    await audit.record({ toolId: "t3", agentId: "a", action: "invoke" });

    const result = await audit.verifyChain();
    expect(result.valid).toBe(true);
  });

  it("respects maxEntries", async () => {
    const small = auditMiddleware({ maxEntries: 3 });
    small.clear();

    for (let i = 0; i < 5; i++) {
      await small.record({ toolId: `t${i}`, agentId: "a", action: "invoke" });
    }
    expect(small.length).toBeLessThanOrEqual(3);
  });

  it("calls custom sink", async () => {
    const sunk: unknown[] = [];
    const withSink = auditMiddleware({
      sink: async (entry) => {
        sunk.push(entry);
      },
    });
    withSink.clear();

    await withSink.record({ toolId: "t", agentId: "a", action: "invoke" });
    expect(sunk).toHaveLength(1);
  });

  it("produces a valid chain under concurrent record() calls", async () => {
    const concurrent = auditMiddleware({ maxEntries: 100 });
    concurrent.clear();

    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        concurrent.record({ toolId: `t${i}`, agentId: "a", action: "invoke" })
      )
    );

    expect(concurrent.length).toBe(25);

    // Every entry must link to the one before it, with no duplicate previousHash.
    const entries = concurrent.getEntries().reverse(); // oldest first
    const seenPrev = new Set<string>();
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].previousHash).toBe(entries[i - 1].hash);
      expect(seenPrev.has(entries[i].previousHash)).toBe(false);
      seenPrev.add(entries[i].previousHash);
    }

    const result = await concurrent.verifyChain();
    expect(result.valid).toBe(true);
  });

  it("verifyChain detects field tampering on a stored entry", async () => {
    // The sink receives the live entry object that is stored inside the chain,
    // so mutating it here mutates the chain's own copy.
    const stored: AuditEntry[] = [];
    const tamperable = auditMiddleware({
      maxEntries: 100,
      sink: async (entry) => {
        stored.push(entry);
      },
    });
    tamperable.clear();

    await tamperable.record({ toolId: "t1", agentId: "a", action: "invoke" });
    await tamperable.record({ toolId: "t2", agentId: "a", action: "complete" });
    await tamperable.record({ toolId: "t3", agentId: "a", action: "invoke" });

    expect((await tamperable.verifyChain()).valid).toBe(true);

    // Tamper a covered field without touching the hash. Linkage stays intact,
    // but hash recomputation must catch the mismatch.
    stored[1].toolId = "TAMPERED";

    const result = await tamperable.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it("two middleware instances keep independent chains", async () => {
    const a = auditMiddleware({ maxEntries: 100 });
    const b = auditMiddleware({ maxEntries: 100 });
    a.clear();
    b.clear();

    await a.record({ toolId: "ta", agentId: "agent-a", action: "invoke" });
    await a.record({ toolId: "ta2", agentId: "agent-a", action: "complete" });

    await b.record({ toolId: "tb", agentId: "agent-b", action: "invoke" });

    expect(a.length).toBe(2);
    expect(b.length).toBe(1);

    // clear() on one must not touch the other.
    a.clear();
    expect(a.length).toBe(0);
    expect(b.length).toBe(1);
    expect((await b.verifyChain()).valid).toBe(true);

    // First entries of independent chains both anchor on genesis.
    const bEntries = b.getEntries();
    expect(bEntries[0].previousHash).toBe(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
  });
});

describe("createGovernedTool", () => {
  const result = (
    decision: "allow" | "deny" | "transform",
    transformedPolicyTarget?: unknown
  ): InterventionPointResult => ({
    verdict: {
      decision,
      reason: decision === "deny" ? "test_denied" : undefined,
      transform:
        decision === "transform"
          ? { path: "$policy_target", value: transformedPolicyTarget }
          : undefined,
    },
    transformedPolicyTarget,
    inputIdentity: "sha256:input",
    enforcedIdentity: decision === "transform" ? "sha256:output" : "sha256:input",
  });

  const control = (
    decision: "allow" | "deny" | "transform" = "allow",
    transformed?: unknown
  ): AgentControl =>
    ({
      runTool: async (
        _toolName: string,
        input: unknown,
        execute: (value: unknown) => Promise<unknown>
      ) => {
        if (decision === "deny") {
          throw new AgentControlBlockedError(
            InterventionPoint.PreToolCall,
            result("deny"),
          );
        }
        const effective = decision === "transform" ? transformed : input;
        return {
          value: await execute(effective),
          preToolCallResult: result(decision, transformed),
          postToolCallResult: result("allow"),
        };
      },
    }) as unknown as AgentControl;

  const mockTool = {
    id: "test-tool",
    description: "A test tool",
    execute: async (input: { value: string }) => ({
      result: `processed: ${input.value}`,
    }),
  };

  it("passes through when all checks pass", async () => {
    const governed = createGovernedTool(mockTool, {
      control: control(),
      trust: {
        minTrustScore: 500,
        getTrustScore: async () => 750,
      },
      audit: { captureData: true },
    });

    const result = await governed.execute({ value: "hello" });
    expect(result.result).toBe("processed: hello");
  });

  it("blocks on trust failure", async () => {
    const governed = createGovernedTool(mockTool, {
      control: control(),
      trust: {
        minTrustScore: 900,
        getTrustScore: async () => 100,
      },
      agentId: "untrusted-agent",
    });

    await expect(governed.execute({ value: "hello" })).rejects.toThrow(
      "Trust verification failed"
    );
  });

  it("blocks on ACS denial", async () => {
    const entries: AuditEntry[] = [];
    const governed = createGovernedTool(mockTool, {
      control: control("deny"),
      audit: { sink: async (entry) => entries.push(entry) },
    });

    await expect(governed.execute({ value: "hello" })).rejects.toThrow(
      "test_denied"
    );
    expect(entries.at(-1)?.action).toBe("deny");
    expect(entries.at(-1)?.policy?.reason).toBe("test_denied");
  });

  it("applies ACS tool-input transforms", async () => {
    const governed = createGovernedTool(mockTool, {
      control: control("transform", { value: "redacted" }),
    });

    const output = await governed.execute({ value: "secret" });
    expect(output.result).toBe("processed: redacted");
  });
});
