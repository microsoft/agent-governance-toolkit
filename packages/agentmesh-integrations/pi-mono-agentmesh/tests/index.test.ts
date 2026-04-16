// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { beforeEach, describe, expect, it, vi } from "vitest";

const { createAgentSessionMock, loaderInstances } = vi.hoisted(() => ({
  createAgentSessionMock: vi.fn(),
  loaderInstances: [] as Array<{
    options: Record<string, unknown>;
    reload: ReturnType<typeof vi.fn>;
  }>,
}));

vi.mock("@mariozechner/pi-coding-agent", async () => {
  class DefaultResourceLoader {
    public readonly options: Record<string, unknown>;
    public readonly reload = vi.fn(async () => undefined);

    constructor(options: Record<string, unknown>) {
      this.options = options;
      loaderInstances.push({ options, reload: this.reload });
    }
  }

  return {
    DefaultResourceLoader,
    createAgentSession: createAgentSessionMock,
  };
});

import {
  GovernedPiSession,
  PiAgentMeshGovernance,
  createGovernanceExtension,
  shouldSkipHistoryHydration,
} from "../src";

describe("PiAgentMeshGovernance", () => {
  it("allows built-in tools and denies unknown tools by default", () => {
    const governance = new PiAgentMeshGovernance();

    expect(governance.evaluateToolCall("read", { path: "README.md" }).verdict).toBe(
      "allow"
    );
    expect(governance.evaluateToolCall("deploy", { env: "prod" }).verdict).toBe(
      "deny"
    );
  });

  it("reviews or denies risky bash commands", () => {
    const governance = new PiAgentMeshGovernance();

    const review = governance.evaluateToolCall("bash", {
      command: "git push origin main",
    });
    const deny = governance.evaluateToolCall("bash", {
      command: "rm -rf /",
    });

    expect(review.verdict).toBe("review");
    expect(review.reason).toContain("requires approval");
    expect(deny.verdict).toBe("deny");
    expect(deny.reason).toContain("Blocked bash command");
  });

  it("records prompts, tool results, and provider requests in a verifiable audit log", () => {
    const governance = new PiAgentMeshGovernance();

    governance.recordPrompt("Summarize the repo", false);
    governance.recordToolResult("read", { path: "README.md" }, { content: "hello" });
    governance.recordProviderRequest({ model: "claude", messages: [{ role: "user" }] });

    const auditLog = governance.getAuditLog();
    expect(auditLog.map((entry) => entry.kind)).toEqual([
      "prompt",
      "tool_result",
      "provider_request",
    ]);
    expect(governance.verifyAuditLog()).toBe(true);
  });
});

describe("createGovernanceExtension", () => {
  it("blocks reviewed or denied tool calls and records downstream events", async () => {
    const governance = new PiAgentMeshGovernance();
    const handlers: Record<string, Function> = {};
    const logger = { warn: vi.fn() };

    createGovernanceExtension(governance, logger)({
      on(event: string, handler: Function) {
        handlers[event] = handler;
      },
    } as any);

    const blocked = await handlers.tool_call({
      type: "tool_call",
      toolCallId: "1",
      toolName: "bash",
      input: { command: "git push origin main" },
    });

    expect(blocked).toEqual({
      block: true,
      reason: expect.stringContaining("requires approval"),
    });
    expect(logger.warn).toHaveBeenCalledOnce();

    await handlers.tool_result({
      type: "tool_result",
      toolCallId: "1",
      toolName: "read",
      input: { path: "README.md" },
      content: [{ type: "text", text: "hello" }],
      isError: false,
      details: undefined,
    });
    await handlers.before_provider_request({
      type: "before_provider_request",
      payload: { model: "claude", messages: [{ role: "user" }] },
    });

    expect(governance.getAuditLog().map((entry) => entry.kind)).toEqual([
      "tool_call",
      "tool_result",
      "provider_request",
    ]);
  });
});

describe("GovernedPiSession", () => {
  const fakeSession = {
    prompt: vi.fn(async () => undefined),
    abort: vi.fn(async () => undefined),
    dispose: vi.fn(() => undefined),
    isStreaming: false,
    agent: {
      continue: vi.fn(async () => undefined),
      state: { messages: [] as any[] },
    },
    model: {
      api: "anthropic-messages",
      provider: "anthropic",
      id: "claude-sonnet",
    },
  };

  beforeEach(() => {
    loaderInstances.length = 0;
    createAgentSessionMock.mockReset();
    fakeSession.prompt.mockClear();
    fakeSession.abort.mockClear();
    fakeSession.dispose.mockClear();
    fakeSession.agent.continue.mockClear();
    fakeSession.agent.state.messages = [];
    createAgentSessionMock.mockResolvedValue({ session: fakeSession });
  });

  it("creates a default resource loader with the governance extension and records prompts", async () => {
    const extraFactory = vi.fn();
    const session = new GovernedPiSession({
      cwd: "/repo",
      agentDir: "/tmp/.pi",
      extensionFactories: [extraFactory],
    });

    await session.start();
    await session.prompt("Inspect the working tree");

    expect(loaderInstances).toHaveLength(1);
    expect(
      (loaderInstances[0].options.extensionFactories as unknown[]).length
    ).toBe(2);
    expect(loaderInstances[0].reload).toHaveBeenCalledOnce();
    expect(createAgentSessionMock).toHaveBeenCalledOnce();
    expect(fakeSession.prompt).toHaveBeenCalledWith("Inspect the working tree", undefined);
    expect(session.auditLog.at(-1)?.kind).toBe("prompt");
  });

  it("hydrates history into the underlying pi session", async () => {
    const session = new GovernedPiSession();

    await session.loadHistory([
      { role: "user", content: "Hello" },
      { role: "assistant", content: "Hi there" },
    ]);

    expect(fakeSession.agent.state.messages).toHaveLength(2);
    expect(fakeSession.agent.state.messages[0]).toEqual({
      role: "user",
      content: "Hello",
    });
    expect(fakeSession.agent.state.messages[1].role).toBe("assistant");
    expect(fakeSession.agent.state.messages[1].content[0].text).toBe("Hi there");
  });

  it("uses a caller-supplied resource loader factory when provided", async () => {
    const resourceLoader = {
      reload: vi.fn(async () => undefined),
    };
    const resourceLoaderFactory = vi.fn(() => resourceLoader);
    const session = new GovernedPiSession({ resourceLoaderFactory });

    await session.start();

    expect(resourceLoaderFactory).toHaveBeenCalledOnce();
    expect(resourceLoader.reload).toHaveBeenCalledOnce();
  });
});

describe("shouldSkipHistoryHydration", () => {
  it("skips a single in-flight user prompt but not longer histories", () => {
    expect(shouldSkipHistoryHydration([{ role: "user", content: "Hi" }])).toBe(
      true
    );
    expect(
      shouldSkipHistoryHydration([
        { role: "user", content: "Hi" },
        { role: "assistant", content: "Hello" },
      ])
    ).toBe(false);
  });
});
