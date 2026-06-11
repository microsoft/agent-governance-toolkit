import {
  AgentControlBlockedError,
  Decision,
  EnforcementMode,
  InterventionPoint,
  InterventionPointResult,
  JsonValue,
  RunResult,
  ToolRunResult,
} from "./index";
import {
  AdapterOptions,
  RunnableControl,
  adapterMethods,
  assertAgentControl,
  assertObject,
  ensureHasMethod,
  extractAdapterOptions,
  hasAgentControlSurface,
  isObject,
  mergeOptions,
  normalizeMode,
  policyJsonValue,
  transformedOr,
} from "./adapter-helpers";

export type { AdapterOptions } from "./adapter-helpers";

const MODEL_METHOD_NAMES = ["invoke", "call", "complete", "generate", "create"];
const TOOL_METHOD_NAMES = ["execute", "call", "invoke", "handler"];
const UNSUPPORTED_BATCH_STREAM_METHODS = new Set<PropertyKey>(["batch", "stream"]);
const UNSUPPORTED_MCP_METHODS = new Set<PropertyKey>([
  "readResource",
  "read_resource",
  "getPrompt",
  "get_prompt",
  "stream",
  "initialize",
]);

function unsupportedAdapterMethod(
  label: string,
  method: string,
  interventionPoint: InterventionPoint = InterventionPoint.Output,
): AgentControlBlockedError {
  return new AgentControlBlockedError(interventionPoint, {
    verdict: {
      decision: Decision.Deny,
      reason: "runtime_error:adapter_unsupported",
      message: `${label} method ${method} is not guarded by this adapter.`,
    },
  });
}

export interface ModelRunResult<TOutput = JsonValue> {
  value: TOutput;
  preModelCallResult: InterventionPointResult;
  postModelCallResult: InterventionPointResult;
}

export interface GuardedModelTurnResult<TOutput = JsonValue> extends ModelRunResult<TOutput> {
  inputResult: InterventionPointResult;
  outputResult: InterventionPointResult;
}

export interface ModelInterventionPointMiddleware<TRequest = JsonValue, TResponse = JsonValue> {
  preModelCall(request: TRequest, options?: AdapterOptions): Promise<InterventionPointResult>;
  postModelCall(response: TResponse, options?: AdapterOptions & { modelRequest?: TRequest }): Promise<InterventionPointResult>;
  run<TOutput extends JsonValue = JsonValue>(
    request: TRequest,
    execute: (request: JsonValue) => Promise<TOutput> | TOutput,
    options?: AdapterOptions,
  ): Promise<ModelRunResult<TOutput | JsonValue>>;
  wrap<TModel>(model: TModel, options?: AdapterOptions): TModel;
}

export interface FullCoverageAgentAdapter<TAgent> {
  guard(agent: TAgent, control: RunnableControl): TAgent;
}

export async function runModel<TOutput extends JsonValue = JsonValue>(
  control: RunnableControl,
  request: JsonValue,
  execute: (request: JsonValue) => Promise<TOutput> | TOutput,
  options: AdapterOptions = {},
): Promise<ModelRunResult<TOutput | JsonValue>> {
  assertAgentControl(control);
  rejectStreamingModelRequest(request);
  const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
  const ambient = { ...(options.snapshot ?? {}) };
  const preModelCallResult = await control.evaluateInterventionPoint(
    InterventionPoint.PreModelCall,
    { ...ambient, model_request: policyJsonValue(request) },
    mode,
  );
  await control.enforce(InterventionPoint.PreModelCall, preModelCallResult, mode, options.approvalResolver);
  const effectiveRequest = transformedOr(preModelCallResult, request, mode);
  const response = await execute(effectiveRequest);
  const postModelCallResult = await control.evaluateInterventionPoint(
    InterventionPoint.PostModelCall,
    { ...ambient, model_request: policyJsonValue(effectiveRequest), model_response: policyJsonValue(response) },
    mode,
  );
  await control.enforce(InterventionPoint.PostModelCall, postModelCallResult, mode, options.approvalResolver);
  return {
    value: transformedOr(postModelCallResult, response, mode) as TOutput | JsonValue,
    preModelCallResult,
    postModelCallResult,
  };
}

function rejectStreamingModelRequest(request: JsonValue): void {
  if (!isObject(request) || request.stream !== true) return;
  throw new AgentControlBlockedError(InterventionPoint.PreModelCall, {
    verdict: {
      decision: Decision.Deny,
      reason: "runtime_error:streaming_unsupported",
      message: "Streaming model requests are not guarded by this adapter; use runModelStream for SSE buffering.",
    },
  });
}

export function protectModel(
  control: RunnableControl,
  execute: (request: JsonValue) => Promise<JsonValue> | JsonValue,
  defaultOptions: AdapterOptions = {},
): (request: JsonValue, callOptions?: AdapterOptions) => Promise<ModelRunResult<JsonValue>> {
  assertAgentControl(control);
  return async (request, callOptions = {}) =>
    await runModel(control, request, execute, mergeOptions(defaultOptions, callOptions));
}

export function createModelMiddleware(
  control: RunnableControl,
  defaultOptions: AdapterOptions = {},
): ModelInterventionPointMiddleware {
  assertAgentControl(control);
  return {
    async preModelCall(request, callOptions = {}) {
      const options = mergeOptions(defaultOptions, callOptions);
      const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
      const result = await control.evaluateInterventionPoint(
        InterventionPoint.PreModelCall,
        { ...(options.snapshot ?? {}), model_request: policyJsonValue(request) },
        mode,
      );
      await control.enforce(InterventionPoint.PreModelCall, result, mode, options.approvalResolver);
      return result;
    },
    async postModelCall(response, callOptions = {}) {
      const options = mergeOptions(defaultOptions, callOptions);
      const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
      const snapshot: Record<string, JsonValue> = { ...(options.snapshot ?? {}), model_response: policyJsonValue(response) };
      if (options.modelRequest !== undefined) {
        snapshot.model_request = policyJsonValue(options.modelRequest);
      }
      const result = await control.evaluateInterventionPoint(
        InterventionPoint.PostModelCall,
        snapshot,
        mode,
      );
      await control.enforce(InterventionPoint.PostModelCall, result, mode, options.approvalResolver);
      return result;
    },
    async run(request, execute, callOptions = {}) {
      return await runModel(control, request, execute, mergeOptions(defaultOptions, callOptions));
    },
    wrap(model, callOptions = {}) {
      return wrapModel(control, model, mergeOptions(defaultOptions, callOptions));
    },
  };
}

export function wrapModel<TModel>(
  control: RunnableControl,
  model: TModel,
  defaultOptions: AdapterOptions = {},
): TModel {
  assertAgentControl(control);
  if (typeof model === "function") {
    return (async (request: JsonValue, ...rest: unknown[]) => {
      const options = mergeOptions(defaultOptions, extractAdapterOptions(rest[0]));
      const result = await runModel(
        control,
        request,
        (effectiveRequest) => (model as (...args: unknown[]) => Promise<JsonValue> | JsonValue)(effectiveRequest, ...rest),
        options,
      );
      return result.value;
    }) as TModel;
  }
  assertObject(model, "model");
  const methods = adapterMethods(defaultOptions, MODEL_METHOD_NAMES);
  ensureHasMethod(model, methods, "model");
  return new Proxy(model, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (methods.includes(property) && typeof value === "function") {
        return async (request: JsonValue, ...rest: unknown[]) => {
          const options = mergeOptions(defaultOptions, extractAdapterOptions(rest[0]));
          const result = await runModel(
            control,
            request,
            (effectiveRequest) => value.call(target, effectiveRequest, ...rest) as Promise<JsonValue> | JsonValue,
            options,
          );
          return result.value;
        };
      }
      return value;
    },
  }) as TModel;
}

export async function runLangChainRunnable(
  control: RunnableControl,
  runnable: unknown,
  input: JsonValue,
  config?: unknown,
  options: AdapterOptions = {},
): Promise<JsonValue> {
  if (!hasAgentControlSurface(control)) {
    throw unsupportedAdapterMethod("LangChain runnable", "invoke", InterventionPoint.PreModelCall);
  }
  if (!isObject(runnable) || typeof runnable.invoke !== "function") {
    throw unsupportedAdapterMethod("LangChain runnable", "invoke", InterventionPoint.PreModelCall);
  }
  const mergedOptions = mergeOptions(options, extractAdapterOptions(config));
  const result = await runWithInputModelOutput(
    control,
    input,
    (effectiveInput) => (runnable.invoke as Function)(effectiveInput, config) as Promise<JsonValue> | JsonValue,
    mergedOptions,
  );
  return result.value;
}

export function guardLangChainRunnable<TAgent>(
  control: RunnableControl,
  runnable: TAgent,
  defaultOptions: AdapterOptions = {},
): TAgent {
  if (!hasAgentControlSurface(control)) {
    throw unsupportedAdapterMethod("LangChain runnable", "guardLangChainRunnable", InterventionPoint.PreModelCall);
  }
  if (!isObject(runnable) || (typeof runnable.invoke !== "function" && typeof runnable.ainvoke !== "function")) {
    throw unsupportedAdapterMethod("LangChain runnable", "invoke/ainvoke", InterventionPoint.PreModelCall);
  }
  return new Proxy(runnable, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if ((property === "invoke" || property === "ainvoke") && typeof value === "function") {
        return async (input: JsonValue, config?: unknown, ...rest: unknown[]) => {
          const options = mergeOptions(defaultOptions, extractAdapterOptions(config));
          const result = await runWithInputModelOutput(
            control,
            input,
            (effectiveInput) => value.call(target, effectiveInput, config, ...rest) as Promise<JsonValue> | JsonValue,
            options,
          );
          return result.value;
        };
      }
      if (UNSUPPORTED_BATCH_STREAM_METHODS.has(property) && typeof value === "function") {
        return async () => {
          throw unsupportedAdapterMethod("LangChain runnable", String(property), InterventionPoint.PreModelCall);
        };
      }
      return value;
    },
  }) as TAgent;
}

export function guardLangChainTool<TTool>(
  control: RunnableControl,
  tool: TTool,
  defaultOptions: AdapterOptions = {},
): TTool {
  return wrapToolLike(control, tool, defaultOptions, "LangChain tool");
}

export function createLangChainAdapter(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  assertAgentControl(control);
  return {
    guard<TAgent>(runnable: TAgent, callOptions: AdapterOptions = {}) {
      return guardLangChainRunnable(control, runnable, mergeOptions(defaultOptions, callOptions));
    },
    guardAgent<TAgent>(agent: TAgent, callOptions: AdapterOptions = {}) {
      return guardLangChainRunnable(control, agent, mergeOptions(defaultOptions, callOptions));
    },
    wrapRunnable<TAgent>(runnable: TAgent, callOptions: AdapterOptions = {}) {
      return guardLangChainRunnable(control, runnable, mergeOptions(defaultOptions, callOptions));
    },
    guardTool<TTool>(tool: TTool, callOptions: AdapterOptions = {}) {
      return guardLangChainTool(control, tool, mergeOptions(defaultOptions, callOptions));
    },
    wrapTool<TTool>(tool: TTool, callOptions: AdapterOptions = {}) {
      return guardLangChainTool(control, tool, mergeOptions(defaultOptions, callOptions));
    },
    async invoke(runnable: unknown, input: JsonValue, config?: unknown, callOptions: AdapterOptions = {}) {
      return await runLangChainRunnable(control, runnable, input, config, mergeOptions(defaultOptions, callOptions));
    },
  };
}

export async function runOpenAIAgent(
  control: RunnableControl,
  runner: unknown,
  agent: unknown,
  input: JsonValue,
  runOptions: unknown = {},
  options: AdapterOptions = {},
): Promise<JsonValue> {
  assertAgentControl(control);
  const mergedOptions = mergeOptions(options, extractAdapterOptions(runOptions));
  const result = await runWithInputModelOutput(
    control,
    input,
    (effectiveInput) => callOpenAIRunner(runner, agent, effectiveInput, runOptions),
    mergedOptions,
  );
  return result.value;
}

export function wrapOpenAIRunner<TRunner>(
  control: RunnableControl,
  runner: TRunner,
  defaultOptions: AdapterOptions = {},
): TRunner {
  assertAgentControl(control);
  if (typeof runner === "function") {
    return (async (agent: unknown, input: JsonValue, runOptions: unknown = {}) =>
      await runOpenAIAgent(control, runner, agent, input, runOptions, defaultOptions)) as TRunner;
  }
  assertObject(runner, "OpenAI runner");
  if (typeof runner.run !== "function") {
    throw new TypeError("OpenAI Agents runner must expose run(agent, input, options?)");
  }
  return new Proxy(runner, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property === "run" && typeof value === "function") {
        return async (agent: unknown, input: JsonValue, runOptions: unknown = {}) =>
          await runOpenAIAgent(control, target, agent, input, runOptions, defaultOptions);
      }
      if (typeof value === "function") {
        return async () => {
          throw unsupportedAdapterMethod("OpenAI Agents runner", String(property), InterventionPoint.Input);
        };
      }
      return value;
    },
  }) as TRunner;
}

export function guardOpenAIAgent(
  control: RunnableControl,
  agent: unknown,
  runner: unknown,
  defaultOptions: AdapterOptions = {},
) {
  assertAgentControl(control);
  return {
    agent,
    async run(input: JsonValue, runOptions: unknown = {}) {
      return await runOpenAIAgent(control, runner, agent, input, runOptions, defaultOptions);
    },
  };
}

export function wrapOpenAITool<TTool>(
  control: RunnableControl,
  tool: TTool,
  defaultOptions: AdapterOptions = {},
): TTool {
  assertAgentControl(control);
  assertObject(tool, "OpenAI Agents tool");
  const toolName = defaultOptions.toolName ?? (typeof tool.name === "string" ? tool.name : undefined);
  if (!toolName) {
    throw new TypeError("OpenAI Agents tool must have a name or options.toolName");
  }
  if (typeof tool.invoke !== "function") {
    throw new TypeError("OpenAI Agents tool must expose invoke(runContext, input, details?)");
  }
  return new Proxy(tool, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property === "invoke" && typeof value === "function") {
        return async (runContext: unknown, input: unknown, details: unknown = {}) => {
          const options = mergeOptions(defaultOptions, extractAdapterOptions(details));
          const parsedInput = parseOpenAIToolInput(input);
          const result = await control.runTool(
            toolName,
            parsedInput.policyValue,
            (effectiveArgs) => value.call(
              target,
              runContext,
              rebuildOpenAIToolInput(input, parsedInput.policyValue, effectiveArgs),
              details,
            ) as Promise<JsonValue> | JsonValue,
            withSyntheticToolCallId(options, toolName),
          );
          return result.value;
        };
      }
      return value;
    },
  }) as TTool;
}

export function createOpenAIAgentsAdapter(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  assertAgentControl(control);
  return {
    wrapRunner<TRunner>(runner: TRunner, callOptions: AdapterOptions = {}) {
      return wrapOpenAIRunner(control, runner, mergeOptions(defaultOptions, callOptions));
    },
    guardAgent(agent: unknown, runner: unknown, callOptions: AdapterOptions = {}) {
      return guardOpenAIAgent(control, agent, runner, mergeOptions(defaultOptions, callOptions));
    },
    wrapTool<TTool>(tool: TTool, callOptions: AdapterOptions = {}) {
      return wrapOpenAITool(control, tool, mergeOptions(defaultOptions, callOptions));
    },
    guardTool<TTool>(tool: TTool, callOptions: AdapterOptions = {}) {
      return wrapOpenAITool(control, tool, mergeOptions(defaultOptions, callOptions));
    },
    async run(runner: unknown, agent: unknown, input: JsonValue, runOptions: unknown = {}, callOptions: AdapterOptions = {}) {
      return await runOpenAIAgent(control, runner, agent, input, runOptions, mergeOptions(defaultOptions, callOptions));
    },
  };
}

export async function runAnthropicMessage(
  control: RunnableControl,
  client: unknown,
  request: JsonValue,
  requestOptions: unknown = {},
  options: AdapterOptions = {},
): Promise<JsonValue> {
  assertAgentControl(control);
  failClosedIfAnthropicStreaming(request);
  const { create, target } = getAnthropicCreate(client);
  const mergedOptions = mergeOptions(options, extractAdapterOptions(requestOptions));
  const result = await runWithInputModelOutput(
    control,
    request,
    (effectiveRequest) => create.call(target, effectiveRequest, requestOptions) as Promise<JsonValue> | JsonValue,
    mergedOptions,
  );
  return result.value;
}

function failClosedIfAnthropicStreaming(request: JsonValue): void {
  if (!isObject(request) || request.stream !== true) return;
  throw new AgentControlBlockedError(InterventionPoint.PostModelCall, {
    verdict: {
      decision: Decision.Deny,
      reason: "runtime_error:streaming_unsupported",
      message: "Anthropic streaming responses are not guarded by this adapter.",
    },
  });
}

export function wrapAnthropicClient<TClient>(
  control: RunnableControl,
  client: TClient,
  defaultOptions: AdapterOptions = {},
): TClient {
  assertAgentControl(control);
  assertObject(client, "Anthropic client");
  if (isObject(client.messages) && typeof client.messages.create === "function") {
    return new Proxy(client, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (property === "messages" && isObject(value)) {
          return new Proxy(value, {
            get(messagesTarget, messagesProperty, messagesReceiver) {
              const messageValue = Reflect.get(messagesTarget, messagesProperty, messagesReceiver);
              if (messagesProperty === "create" && typeof messageValue === "function") {
                return async (request: JsonValue, requestOptions: unknown = {}) =>
                  await runAnthropicMessage(control, target, request, requestOptions, defaultOptions);
              }
              return messageValue;
            },
          });
        }
        return value;
      },
    }) as TClient;
  }
  return wrapModel(control, client, { ...defaultOptions, methodName: "create" });
}

export function wrapAnthropicTool<TTool>(
  control: RunnableControl,
  tool: TTool,
  defaultOptions: AdapterOptions = {},
): TTool {
  return wrapToolLike(control, tool, defaultOptions, "Anthropic tool");
}

export function createAnthropicAdapter(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  assertAgentControl(control);
  return {
    wrapClient<TClient>(client: TClient, callOptions: AdapterOptions = {}) {
      return wrapAnthropicClient(control, client, mergeOptions(defaultOptions, callOptions));
    },
    wrapTool<TTool>(tool: TTool, callOptions: AdapterOptions = {}) {
      return wrapAnthropicTool(control, tool, mergeOptions(defaultOptions, callOptions));
    },
    async run(client: unknown, request: JsonValue, requestOptions: unknown = {}, callOptions: AdapterOptions = {}) {
      return await runAnthropicMessage(control, client, request, requestOptions, mergeOptions(defaultOptions, callOptions));
    },
  };
}

export function wrapMcpToolProvider<TProvider>(
  control: RunnableControl,
  provider: TProvider,
  defaultOptions: AdapterOptions = {},
): TProvider {
  if (!hasAgentControlSurface(control)) {
    throw unsupportedAdapterMethod("MCP tool provider", "wrapMcpToolProvider", InterventionPoint.PreToolCall);
  }
  if (!isObject(provider)) {
    throw unsupportedAdapterMethod("MCP tool provider", "callTool/call_tool", InterventionPoint.PreToolCall);
  }
  if (typeof provider.callTool !== "function" && typeof provider.call_tool !== "function") {
    throw unsupportedAdapterMethod("MCP tool provider", "callTool/call_tool", InterventionPoint.PreToolCall);
  }
  return new Proxy(provider, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if ((property === "callTool" || property === "call_tool") && typeof value === "function") {
        return async (...args: unknown[]) => {
          const parsed = parseMcpToolCall(args);
          const options = mergeOptions(defaultOptions, extractAdapterOptions(parsed.callOptions));
          const result = await control.runTool(
            parsed.toolName,
            parsed.toolArgs,
            (effectiveArgs) => value.apply(target, rebuildMcpToolCall(args, effectiveArgs)) as Promise<JsonValue> | JsonValue,
            withSyntheticToolCallId(options, parsed.toolName),
          );
          return result.value;
        };
      }
      if (UNSUPPORTED_MCP_METHODS.has(property) && typeof value === "function") {
        return async () => {
          throw unsupportedAdapterMethod("MCP tool provider", String(property), InterventionPoint.PreToolCall);
        };
      }
      return value;
    },
  }) as TProvider;
}

export function createMcpToolProviderAdapter(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  assertAgentControl(control);
  return {
    wrapProvider<TProvider>(provider: TProvider, callOptions: AdapterOptions = {}) {
      return wrapMcpToolProvider(control, provider, mergeOptions(defaultOptions, callOptions));
    },
  };
}

export function createOpenClawAdapter(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  assertAgentControl(control);
  return {
    name: "agentControlOpenClaw",
    guardAgent<TAgent>(agent: TAgent, callOptions: AdapterOptions = {}) {
      return guardOpenClawAgentHarness(control, agent, mergeOptions(defaultOptions, callOptions));
    },
    wrapModel<TModel>(model: TModel, callOptions: AdapterOptions = {}) {
      return wrapModel(control, model, mergeOptions(defaultOptions, callOptions));
    },
    wrapTool(toolName: string, execute: (args: JsonValue) => Promise<JsonValue> | JsonValue, overrideControl = control) {
      if (!overrideControl || typeof overrideControl.protectTool !== "function") {
        throw new Error(
          "OpenClaw tool wrapping requires an AgentControl instance with protectTool().",
        );
      }
      return overrideControl.protectTool(toolName, execute, defaultOptions);
    },
    plugin(pluginOptions: AdapterOptions = {}) {
      assertAgentControl(control);
      return createOpenClawHookPlugin(control, mergeOptions(defaultOptions, pluginOptions));
    },
  };
}

export function createUnsupportedFrameworkAdapter(frameworkName: string) {
  return {
    guardAgent() {
      throw new AgentControlBlockedError(InterventionPoint.Input, {
        verdict: {
          decision: Decision.Deny,
          reason: "runtime_error:adapter_unsupported",
          message: `Full-coverage ${frameworkName} adapter is not implemented yet; ` +
            "use AgentControl.run() or AgentControl.protectTool() with explicit hooks.",
        },
      });
    },
    wrapModel() {
      throw new AgentControlBlockedError(InterventionPoint.Input, {
        verdict: {
          decision: Decision.Deny,
          reason: "runtime_error:adapter_unsupported",
          message: `Model middleware for ${frameworkName} is not implemented yet.`,
        },
      });
    },
    wrapTool(toolName: string, execute: (args: JsonValue) => Promise<JsonValue> | JsonValue, control: RunnableControl) {
      if (!control || typeof control.protectTool !== "function") {
        throw new TypeError("wrapTool requires an AgentControl instance");
      }
      return control.protectTool(toolName, execute);
    },
  };
}

async function runWithInputModelOutput(
  control: RunnableControl,
  input: JsonValue,
  execute: (input: JsonValue) => Promise<JsonValue> | JsonValue,
  options: AdapterOptions = {},
): Promise<GuardedModelTurnResult<JsonValue>> {
  const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
  const ambient = { ...(options.snapshot ?? {}) };
  const inputResult = await control.evaluateInterventionPoint(
    InterventionPoint.Input,
    { ...ambient, input: policyJsonValue(input) },
    mode,
  );
  await control.enforce(InterventionPoint.Input, inputResult, mode, options.approvalResolver);
  const effectiveInput = transformedOr(inputResult, input, mode);
  const modelRun = await runModel(control, effectiveInput, execute, {
    ...options,
    snapshot: { ...ambient, input: policyJsonValue(effectiveInput) },
  });
  const outputResult = await control.evaluateInterventionPoint(
    InterventionPoint.Output,
    { ...ambient, input: policyJsonValue(effectiveInput), output: policyJsonValue(modelRun.value) },
    mode,
  );
  await control.enforce(InterventionPoint.Output, outputResult, mode, options.approvalResolver);
  return {
    value: transformedOr(outputResult, modelRun.value, mode),
    inputResult,
    preModelCallResult: modelRun.preModelCallResult,
    postModelCallResult: modelRun.postModelCallResult,
    outputResult,
  };
}

function createOpenClawHookPlugin(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  const modelMiddleware = createModelMiddleware(control, defaultOptions);
  const hooks = createOpenClawHookHandlers(control, defaultOptions);
  return {
    name: "agentControlOpenClaw",
    capabilities: Object.freeze({
      fullCoverageAgent: true,
      modelHooks: true,
      toolWrapper: true,
      nativeHooks: true,
    }),
    hooks,
    register(api: unknown) {
      registerOpenClawHooks(api, hooks);
    },
    async beforeModelCall(request: JsonValue, hookContext: AdapterOptions = {}) {
      const options = mergeOptions(mergeOptions(defaultOptions, hookContext), extractAdapterOptions(hookContext));
      const result = await modelMiddleware.preModelCall(request, options);
      return { value: transformedOr(result, request, normalizeMode(options.mode ?? EnforcementMode.Enforce)), result };
    },
    async afterModelCall(response: JsonValue, hookContext: AdapterOptions = {}) {
      const options = mergeOptions(mergeOptions(defaultOptions, hookContext), extractAdapterOptions(hookContext));
      const modelRequest = hookContext.modelRequest ?? hookContext.model_request;
      const result = await modelMiddleware.postModelCall(response, { ...options, modelRequest });
      return { value: transformedOr(result, response, normalizeMode(options.mode ?? EnforcementMode.Enforce)), result };
    },
    wrapTool(toolName: string, execute: (args: JsonValue) => Promise<JsonValue> | JsonValue, callOptions: AdapterOptions = {}) {
      return control.protectTool(toolName, execute, mergeOptions(defaultOptions, callOptions));
    },
    guardTool(toolName: string, execute: (args: JsonValue) => Promise<JsonValue> | JsonValue, callOptions: AdapterOptions = {}) {
      return this.wrapTool(toolName, execute, callOptions);
    },
  };
}

function guardOpenClawAgentHarness<TAgent>(
  control: RunnableControl,
  agent: TAgent,
  defaultOptions: AdapterOptions = {},
): TAgent {
  assertAgentControl(control);
  assertObject(agent, "OpenClaw agent harness");
  if (typeof agent.runAttempt !== "function" || typeof agent.supports !== "function") {
    throw new TypeError("OpenClaw guardAgent expects an AgentHarness with supports(ctx) and runAttempt(params)");
  }
  return new Proxy(agent, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property === "runAttempt" && typeof value === "function") {
        return async (params: JsonValue, ...rest: unknown[]) => {
          const options = mergeOptions(defaultOptions, extractAdapterOptions(rest[0]));
          const agentMetadata = openClawAgentMetadata(target);
          return await control.withSession(
            agentMetadata,
            async (session) => {
              const result = await control.run(
                params,
                (effectiveParams) => value.call(target, effectiveParams, ...rest) as Promise<JsonValue> | JsonValue,
                options,
              );
              session.summary = { agent: agentMetadata, result: result.value };
              return result.value;
            },
            options,
          );
        };
      }
      return value;
    },
  }) as TAgent;
}

function createOpenClawHookHandlers(control: RunnableControl, defaultOptions: AdapterOptions = {}) {
  return {
    async before_agent_run(event: unknown, context: unknown = {}) {
      const prompt = propertyJson(event, "prompt") ?? "";
      await enforceOpenClawHookPoint(control, InterventionPoint.Input, { input: prompt }, defaultOptions, context);
      return { outcome: "pass" };
    },
    async llm_input(event: unknown, context: unknown = {}) {
      await enforceOpenClawHookPoint(control, InterventionPoint.PreModelCall, { model_request: toJsonValue(event) }, defaultOptions, context);
    },
    async llm_output(event: unknown, context: unknown = {}) {
      await enforceOpenClawHookPoint(control, InterventionPoint.PostModelCall, { model_response: toJsonValue(event) }, defaultOptions, context);
    },
    async before_tool_call(event: unknown, context: unknown = {}) {
      const toolName = propertyString(event, "toolName") ?? propertyString(context, "toolName");
      if (!toolName) throw new TypeError("OpenClaw before_tool_call event requires toolName");
      const params = propertyJson(event, "params") ?? {};
      const result = await enforceOpenClawHookPoint(
        control,
        InterventionPoint.PreToolCall,
        { tool_call: openClawToolCall(event, context, toolName, params) },
        defaultOptions,
        context,
      );
      const mode = normalizeMode((extractAdapterOptions(context).mode ?? defaultOptions.mode) ?? EnforcementMode.Enforce);
      return { params: transformedOr(result, params, mode) };
    },
    async after_tool_call(event: unknown, context: unknown = {}) {
      const toolName = propertyString(event, "toolName") ?? propertyString(context, "toolName");
      if (!toolName) throw new TypeError("OpenClaw after_tool_call event requires toolName");
      await enforceOpenClawHookPoint(
        control,
        InterventionPoint.PostToolCall,
        {
          tool_call: openClawToolCall(event, context, toolName, propertyJson(event, "params") ?? {}),
          tool_result: propertyJson(event, "result") ?? {},
        },
        defaultOptions,
        context,
      );
    },
    async session_start(event: unknown, context: unknown = {}) {
      await enforceOpenClawHookPoint(control, InterventionPoint.AgentStartup, { agent: toJsonValue(event) }, defaultOptions, context);
    },
    async before_agent_finalize(event: unknown, context: unknown = {}) {
      await enforceOpenClawHookPoint(control, InterventionPoint.Output, { output: toJsonValue(event) }, defaultOptions, context);
    },
    async session_end(event: unknown, context: unknown = {}) {
      await enforceOpenClawHookPoint(control, InterventionPoint.AgentShutdown, { summary: toJsonValue(event) }, defaultOptions, context);
    },
  };
}

async function enforceOpenClawHookPoint(
  control: RunnableControl,
  interventionPoint: InterventionPoint,
  snapshot: Record<string, JsonValue>,
  defaultOptions: AdapterOptions,
  context: unknown,
): Promise<InterventionPointResult> {
  const options = mergeOptions(defaultOptions, extractAdapterOptions(context));
  const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
  const result = await control.evaluateInterventionPoint(
    interventionPoint,
    { ...(options.snapshot ?? {}), ...snapshot },
    mode,
  );
  await control.enforce(interventionPoint, result, mode, options.approvalResolver);
  return result;
}

function registerOpenClawHooks(api: unknown, hooks: Record<string, Function>): void {
  assertObject(api, "OpenClaw plugin API");
  for (const [hookName, handler] of Object.entries(hooks)) {
    if (typeof api.on === "function") {
      api.on(hookName, handler);
    } else if (typeof api.registerHook === "function") {
      api.registerHook(hookName, handler);
    } else {
      throw new TypeError("OpenClaw plugin API must expose on(hookName, handler) or registerHook(hookName, handler)");
    }
  }
}

function openClawAgentMetadata(agent: Record<PropertyKey, unknown>): JsonValue {
  return {
    id: typeof agent.id === "string" ? agent.id : "openclaw-agent",
    label: typeof agent.label === "string" ? agent.label : "OpenClaw agent",
    pluginId: typeof agent.pluginId === "string" ? agent.pluginId : "",
  };
}

function openClawToolCall(event: unknown, context: unknown, name: string, args: JsonValue): Record<string, JsonValue> {
  const id = openClawToolCallId(event, context);
  const toolCall: Record<string, JsonValue> = { name, args };
  if (id !== undefined) toolCall.id = id;
  return toolCall;
}

function openClawToolCallId(event: unknown, context: unknown): string | undefined {
  const id = propertyString(event, "toolCallId") ?? propertyString(context, "toolCallId");
  return id !== undefined && id.trim().length > 0 ? id : undefined;
}

function wrapToolLike<TTool>(
  control: RunnableControl,
  tool: TTool,
  defaultOptions: AdapterOptions,
  label: string,
): TTool {
  assertAgentControl(control);
  if (typeof tool === "function") {
    const toolName = defaultOptions.toolName ?? tool.name;
    if (!toolName) {
      throw new TypeError(`${label} function requires options.toolName when it has no name`);
    }
    return (async (args: JsonValue, ...rest: unknown[]) => {
      const options = mergeOptions(defaultOptions, extractAdapterOptions(rest[0]));
      const result = await control.runTool(
        toolName,
        args,
        (effectiveArgs) => (tool as (...args: unknown[]) => Promise<JsonValue> | JsonValue)(effectiveArgs, ...rest),
        withSyntheticToolCallId(options, toolName),
      );
      return result.value;
    }) as TTool;
  }
  assertObject(tool, label);
  const toolName = defaultOptions.toolName ?? (typeof tool.name === "string" ? tool.name : undefined) ??
    (typeof tool.toolName === "string" ? tool.toolName : undefined);
  if (!toolName) {
    throw new TypeError(`${label} must have a name or options.toolName`);
  }
  const methods = adapterMethods(defaultOptions, TOOL_METHOD_NAMES);
  ensureHasMethod(tool, methods, label);
  return new Proxy(tool, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (methods.includes(property) && typeof value === "function") {
        return async (args: JsonValue, ...rest: unknown[]) => {
          const options = mergeOptions(defaultOptions, extractAdapterOptions(rest[0]));
          const result = await control.runTool(
            toolName,
            args,
            (effectiveArgs) => value.call(target, effectiveArgs, ...rest) as Promise<JsonValue> | JsonValue,
            withSyntheticToolCallId(options, toolName),
          );
          return result.value;
        };
      }
      if (UNSUPPORTED_BATCH_STREAM_METHODS.has(property) && typeof value === "function") {
        return async () => {
          throw unsupportedAdapterMethod(label, String(property), InterventionPoint.PreToolCall);
        };
      }
      return value;
    },
  }) as TTool;
}

function callOpenAIRunner(
  runner: unknown,
  agent: unknown,
  input: JsonValue,
  runOptions: unknown,
): Promise<JsonValue> | JsonValue {
  if (typeof runner === "function") {
    return (runner as Function)(agent, input, runOptions) as Promise<JsonValue> | JsonValue;
  }
  if (isObject(runner) && typeof runner.run === "function") {
    return (runner.run as Function).call(runner, agent, input, runOptions) as Promise<JsonValue> | JsonValue;
  }
  throw new TypeError("OpenAI Agents runner must be a function or expose run(agent, input, options?)");
}

function getAnthropicCreate(client: unknown): { create: Function; target: unknown } {
  if (isObject(client) && isObject(client.messages) && typeof client.messages.create === "function") {
    return { create: client.messages.create as Function, target: client.messages };
  }
  if (isObject(client) && typeof client.create === "function") {
    return { create: client.create as Function, target: client };
  }
  throw new TypeError("Anthropic client must expose messages.create(request, options?) or create(request, options?)");
}

function parseMcpToolCall(args: unknown[]): { toolName: string; toolArgs: JsonValue; callOptions: unknown } {
  const [first, second, third] = args;
  if (isObject(first)) {
    const toolName = stringProperty(first, "name") ?? stringProperty(first, "tool") ?? stringProperty(first, "toolName");
    if (!toolName) {
      throw new TypeError("MCP object call must include name, tool, or toolName");
    }
    return {
      toolName,
      toolArgs: jsonProperty(first, "arguments") ?? jsonProperty(first, "args") ?? jsonProperty(first, "input") ?? {},
      callOptions: second,
    };
  }
  if (typeof first !== "string") {
    throw new TypeError("MCP positional call must start with a tool name");
  }
  return { toolName: first, toolArgs: toJsonValue(second ?? {}), callOptions: third };
}

function rebuildMcpToolCall(originalArgs: unknown[], effectiveArgs: JsonValue): unknown[] {
  const [first, second, ...rest] = originalArgs;
  if (isObject(first)) {
    const request = { ...first };
    if (Object.prototype.hasOwnProperty.call(request, "arguments")) {
      request.arguments = effectiveArgs;
    } else if (Object.prototype.hasOwnProperty.call(request, "args")) {
      request.args = effectiveArgs;
    } else if (Object.prototype.hasOwnProperty.call(request, "input")) {
      request.input = effectiveArgs;
    } else {
      request.arguments = effectiveArgs;
    }
    return [request, second, ...rest];
  }
  return [first, effectiveArgs, ...rest];
}

function stringProperty(value: Record<string, unknown>, property: string): string | undefined {
  const propertyValue = value[property];
  return typeof propertyValue === "string" ? propertyValue : undefined;
}

function propertyString(value: unknown, property: string): string | undefined {
  return isObject(value) ? stringProperty(value, property) : undefined;
}

function propertyJson(value: unknown, property: string): JsonValue | undefined {
  return isObject(value) ? jsonProperty(value, property) : undefined;
}

function jsonProperty(value: Record<string, unknown>, property: string): JsonValue | undefined {
  return Object.prototype.hasOwnProperty.call(value, property) ? toJsonValue(value[property]) : undefined;
}

function toJsonValue(value: unknown): JsonValue {
  return value as JsonValue;
}

function parseOpenAIToolInput(input: unknown): { policyValue: JsonValue; parsedJsonString: boolean } {
  if (typeof input === "string") {
    try {
      return { policyValue: policyJsonValue(JSON.parse(input)), parsedJsonString: true };
    } catch {
      return { policyValue: input, parsedJsonString: false };
    }
  }
  return { policyValue: policyJsonValue(input), parsedJsonString: false };
}

function rebuildOpenAIToolInput(originalInput: unknown, originalPolicyValue: JsonValue, effectiveArgs: JsonValue): unknown {
  if (typeof originalInput === "string") {
    if (effectiveArgs === originalPolicyValue) return originalInput;
    return JSON.stringify(effectiveArgs);
  }
  return effectiveArgs;
}

let syntheticToolCallCounter = 0;

function withSyntheticToolCallId(options: AdapterOptions, toolName: string): AdapterOptions {
  if (options.toolCallId !== undefined) return options;
  syntheticToolCallCounter += 1;
  return {
    ...options,
    toolCallId: `acs-${toolName.replace(/[^A-Za-z0-9_.:-]/g, "_")}-${syntheticToolCallCounter}`,
  };
}
