// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  DefaultResourceLoader,
  createAgentSession,
  type AgentSession,
  type CreateAgentSessionOptions,
  type ExtensionAPI,
  type ExtensionFactory,
  type PromptOptions,
  type ResourceLoader,
} from "@mariozechner/pi-coding-agent";
import {
  PiAgentMeshGovernance,
  type PiGovernanceConfig,
  type PiGovernanceLogger,
} from "./governance";

export interface PiConversationMessage {
  role: "user" | "assistant";
  content: unknown;
}

export interface GovernedPiSessionOptions
  extends Omit<CreateAgentSessionOptions, "resourceLoader"> {
  governance?: PiGovernanceConfig;
  extensionFactories?: ExtensionFactory[];
  logger?: PiGovernanceLogger;
  resourceLoaderFactory?: (
    extensionFactories: ExtensionFactory[]
  ) => Promise<ResourceLoader> | ResourceLoader;
}

export class GovernedPiSession {
  private session?: AgentSession;
  private initialized = false;
  private readonly governance: PiAgentMeshGovernance;
  private readonly governanceExtension: ExtensionFactory;

  constructor(private readonly options: GovernedPiSessionOptions = {}) {
    this.governance = new PiAgentMeshGovernance(options.governance);
    this.governanceExtension = createGovernanceExtension(
      this.governance,
      this.options.logger
    );
  }

  get agentDid(): string {
    return this.governance.agentDid;
  }

  get auditLog() {
    return this.governance.getAuditLog();
  }

  get rawSession(): AgentSession | undefined {
    return this.session;
  }

  async start(): Promise<AgentSession> {
    if (this.session) {
      return this.session;
    }

    const { extensionFactories = [], resourceLoaderFactory, ...sessionOptions } =
      this.options;
    const mergedFactories = [...extensionFactories, this.governanceExtension];
    const resourceLoader = resourceLoaderFactory
      ? await resourceLoaderFactory(mergedFactories)
      : new DefaultResourceLoader({
          cwd: sessionOptions.cwd,
          agentDir: sessionOptions.agentDir,
          extensionFactories: mergedFactories,
        });

    await this.governance.initialize();
    await resourceLoader.reload();

    const result = await createAgentSession({
      ...sessionOptions,
      resourceLoader,
    });

    this.session = result.session;
    this.initialized = true;
    return result.session;
  }

  async prompt(text: string, options?: PromptOptions): Promise<void> {
    const session = await this.start();
    this.governance.recordPrompt(text, !!options?.images?.length);
    await session.prompt(text, options);
  }

  async continueResponse(): Promise<void> {
    const session = await this.start();
    await session.agent.continue();
  }

  async loadHistory(history: PiConversationMessage[]): Promise<void> {
    const session = await this.start();

    if (history.length === 0 || shouldSkipHistoryHydration(history)) {
      return;
    }

    session.agent.state.messages = mapHistoryToAgentMessages(
      history,
      session.model
    ) as typeof session.agent.state.messages;
  }

  verifyAuditLog(): boolean {
    return this.governance.verifyAuditLog();
  }

  async stop(): Promise<void> {
    if (!this.session) {
      return;
    }

    try {
      if (this.session.isStreaming) {
        await this.session.abort();
      }
    } finally {
      this.session.dispose();
      this.session = undefined;
      this.initialized = false;
    }
  }

  isStarted(): boolean {
    return this.initialized;
  }
}

export function createGovernanceExtension(
  governance: PiAgentMeshGovernance,
  logger?: PiGovernanceLogger
): ExtensionFactory {
  return (pi: ExtensionAPI) => {
    pi.on("tool_call", async (event) => {
      const decision = governance.evaluateToolCall(
        event.toolName,
        event.input as Record<string, unknown> | undefined
      );

      if (decision.verdict === "allow") {
        return undefined;
      }

      return governance.createBlockedToolResult(decision, event.toolName, logger);
    });

    pi.on("tool_result", async (event) => {
      governance.recordToolResult(
        event.toolName,
        event.input,
        {
          content: event.content,
          isError: event.isError,
          details: event.details,
        }
      );
      return undefined;
    });

    pi.on("before_provider_request", async (event) => {
      governance.recordProviderRequest(event.payload);
      return undefined;
    });
  };
}

export async function createGovernedPiSession(
  options: GovernedPiSessionOptions = {}
): Promise<GovernedPiSession> {
  const session = new GovernedPiSession(options);
  await session.start();
  return session;
}

export function shouldSkipHistoryHydration(
  history: PiConversationMessage[]
): boolean {
  return history.length === 1 && history[0]?.role === "user";
}

function mapHistoryToAgentMessages(history: PiConversationMessage[], model: any): any[] {
  const now = Date.now();

  return history
    .filter(
      (message) =>
        message &&
        typeof message === "object" &&
        message.role &&
        message.content !== undefined
    )
    .map((message, index) => {
      const content =
        typeof message.content === "string"
          ? message.content
          : JSON.stringify(message.content);

      if (message.role === "assistant") {
        return {
          role: "assistant",
          api: model?.api,
          provider: model?.provider,
          model: model?.id,
          stopReason: "stop",
          timestamp: now + index,
          usage: {
            input: 0,
            output: 0,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 0,
            cost: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
              total: 0,
            },
          },
          content: [{ type: "text", text: content }],
        };
      }

      return {
        role: "user",
        content,
      };
    });
}
