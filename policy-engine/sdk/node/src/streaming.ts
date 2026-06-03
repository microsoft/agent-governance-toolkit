import {
  AgentControlBlockedError,
  AgentControlInterruptionError,
  Decision,
  EnforcementMode,
  InterventionPoint,
  JsonValue,
  ModelRunResult,
} from "./index";
import {
  AdapterOptions,
  RunnableControl,
  appliesTransform,
  normalizeMode,
  policyJsonValue,
  transformedOr,
} from "./adapter-helpers";

export const DEFAULT_MAX_STREAM_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_STREAM_EVENTS = 10_000;

const DONE = "[DONE]";
const DATA_FIELD = "data:";
const COMMENT_PREFIX = ":";
const CHUNK_OBJECT = "chat.completion.chunk";
const COMPLETION_OBJECT = "chat.completion";
const ASSISTANT_ROLE = "assistant";
const KNOWN_CHOICE_KEYS = new Set(["index", "delta", "finish_reason"]);
const KNOWN_DELTA_KEYS = new Set(["role", "content", "tool_calls"]);
const PASSTHROUGH_CHUNK_KEYS = ["id", "created", "model"] as const;

export interface StreamingLimits {
  maxStreamBytes?: number;
  maxStreamEvents?: number;
}

export type StreamInput =
  | Uint8Array
  | ArrayBuffer
  | string
  | Iterable<Uint8Array | ArrayBuffer | string>
  | AsyncIterable<Uint8Array | ArrayBuffer | string>;

export interface ModelStreamRunResult extends ModelRunResult<JsonValue> {
  bytes: Uint8Array;
  assembledResponse: JsonValue;
  originalBytes: Uint8Array;
}

class StreamingUnsupportedError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "StreamingUnsupportedError";
    if (options && "cause" in options) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

class ToolCallAccumulator {
  id: string | undefined;
  type: string | undefined;
  name: string | undefined;
  arguments = "";

  merge(fragment: Record<string, unknown>): void {
    this.id = mergeScalar(this.id, fragment.id);
    this.type = mergeScalar(this.type, fragment.type);
    const fn = fragment.function ?? {};
    if (!isObject(fn)) {
      throw new StreamingUnsupportedError("Streaming tool_call.function must be an object.");
    }
    this.name = mergeScalar(this.name, fn.name);
    const args = fn.arguments;
    if (args !== undefined && args !== null) {
      if (typeof args !== "string") {
        throw new StreamingUnsupportedError("Streaming tool_call arguments must be strings.");
      }
      this.arguments += args;
    }
  }

  asJson(): JsonValue {
    return {
      id: this.id ?? "",
      type: this.type ?? "function",
      function: { name: this.name ?? "", arguments: this.arguments },
    };
  }
}

export async function runModelStream(
  control: RunnableControl,
  request: JsonValue,
  execute: (request: JsonValue) => Promise<StreamInput> | StreamInput,
  options: AdapterOptions & StreamingLimits = {},
): Promise<ModelStreamRunResult> {
  let originalBytes: Uint8Array | undefined;
  let assembledResponse: JsonValue | undefined;
  try {
    const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
    const ambient = { ...(options.snapshot ?? {}) };
    const preModelCallResult = await control.evaluateInterventionPoint(
      InterventionPoint.PreModelCall,
      { ...ambient, model_request: policyJsonValue(request) },
      mode,
    );
    await control.enforce(InterventionPoint.PreModelCall, preModelCallResult, mode, options.approvalResolver);
    const effectiveRequest = transformedOr(preModelCallResult, request, mode);
    originalBytes = await collectStreamBytes(await execute(effectiveRequest), options);
    assembledResponse = assembleSseStream(originalBytes, options);
    const postModelCallResult = await control.evaluateInterventionPoint(
      InterventionPoint.PostModelCall,
      { ...ambient, model_request: policyJsonValue(effectiveRequest), model_response: policyJsonValue(assembledResponse) },
      mode,
    );
    await control.enforce(InterventionPoint.PostModelCall, postModelCallResult, mode, options.approvalResolver);
    const value = transformedOr(postModelCallResult, assembledResponse, mode);
    if (originalBytes === undefined || assembledResponse === undefined) {
      throw new StreamingUnsupportedError("Streaming response contained no data chunks.");
    }
    const transformed = mode === EnforcementMode.Enforce &&
      (postModelCallResult.transformedPolicyTargetApplied === true ||
        postModelCallResult.transformedPolicyTarget !== undefined) &&
      appliesTransform(postModelCallResult.verdict.decision);
    const bytes = transformed
      ? synthesizeSseStream(value, assembledResponse)
      : originalBytes;
    return { value, preModelCallResult, postModelCallResult, bytes, assembledResponse, originalBytes };
  } catch (error) {
    if (error instanceof AgentControlInterruptionError) throw error;
    throw failClosed(error instanceof StreamingUnsupportedError ? error.message : "Streaming response failed closed.", error);
  }
}

export function assembleSseStream(raw: Uint8Array | ArrayBuffer | string, limits: StreamingLimits = {}): JsonValue {
  const bytes = rawToBytes(raw);
  if (bytes.byteLength > maxStreamBytes(limits)) {
    throw new StreamingUnsupportedError("Streaming response exceeded the buffering byte limit.");
  }
  const chunks = parseSseChunks(bytes, limits);
  if (chunks.length === 0) {
    throw new StreamingUnsupportedError("Streaming response contained no data chunks.");
  }

  let content = "";
  let finishReason: JsonValue = null;
  const toolCalls = new Map<number, ToolCallAccumulator>();
  const template: Record<string, JsonValue> = {};

  for (const chunk of chunks) {
    if (Object.keys(template).length === 0) {
      for (const key of PASSTHROUGH_CHUNK_KEYS) {
        if (Object.prototype.hasOwnProperty.call(chunk, key)) {
          template[key] = chunk[key] as JsonValue;
        }
      }
    }
    const choicesRaw = chunk.choices || [];
    if (!Array.isArray(choicesRaw)) {
      throw new StreamingUnsupportedError("Streaming chunk choices must be a list.");
    }
    if (choicesRaw.length === 0) continue;
    if (choicesRaw.length > 1) {
      throw new StreamingUnsupportedError("Multi-choice streaming responses are not guarded.");
    }
    const choice = choicesRaw[0];
    if (!isObject(choice)) {
      throw new StreamingUnsupportedError("Streaming choice must be an object.");
    }
    const choiceIndex = Object.prototype.hasOwnProperty.call(choice, "index") ? choice.index : 0;
    if (choiceIndex !== 0) {
      throw new StreamingUnsupportedError("Multi-choice streaming responses are not guarded.");
    }
    if (carriesUnrepresentedData(choice, KNOWN_CHOICE_KEYS)) {
      throw new StreamingUnsupportedError("Streaming choice carried unsupported fields.");
    }

    const deltaRaw = choice.delta || {};
    if (!isObject(deltaRaw)) {
      throw new StreamingUnsupportedError("Streaming choice delta must be an object.");
    }
    if (carriesUnrepresentedData(deltaRaw, KNOWN_DELTA_KEYS)) {
      throw new StreamingUnsupportedError("Streaming delta carried unsupported fields.");
    }
    const piece = deltaRaw.content;
    if (piece !== undefined && piece !== null) {
      if (typeof piece !== "string") {
        throw new StreamingUnsupportedError("Streaming delta content must be a string.");
      }
      content += piece;
    }
    mergeToolCallFragments(deltaRaw.tool_calls, toolCalls);
    if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
      finishReason = choice.finish_reason as JsonValue;
    }
  }

  const message: Record<string, JsonValue> = { role: ASSISTANT_ROLE, content };
  if (toolCalls.size > 0) {
    message.tool_calls = [...toolCalls.keys()].sort((a, b) => a - b).map((index) => toolCalls.get(index)?.asJson() ?? null);
  }
  return {
    ...template,
    object: COMPLETION_OBJECT,
    choices: [{ index: 0, message, finish_reason: finishReason }],
  };
}

export function synthesizeSseStream(response: JsonValue, template: JsonValue): Uint8Array {
  if (!isObject(response)) {
    throw new StreamingUnsupportedError("Transformed streaming response must be an object.");
  }
  const choices = response.choices;
  if (!Array.isArray(choices) || choices.length !== 1 || !isObject(choices[0])) {
    throw new StreamingUnsupportedError("Transformed streaming response must carry a choice.");
  }
  const choice = choices[0];
  if (choice.index !== undefined && choice.index !== 0) {
    throw new StreamingUnsupportedError("Transformed streaming response must carry one zero-index choice.");
  }
  const message = choice.message || {};
  if (!isObject(message)) {
    throw new StreamingUnsupportedError("Transformed streaming choice must carry a message.");
  }

  const delta: Record<string, JsonValue> = { role: ASSISTANT_ROLE };
  if (message.content !== undefined && message.content !== null) {
    if (typeof message.content !== "string") {
      throw new StreamingUnsupportedError("Transformed streaming content must be a string.");
    }
    delta.content = message.content;
  }
  const toolCalls = message.tool_calls;
  if (toolCalls !== undefined && toolCalls !== null) {
    if (!Array.isArray(toolCalls)) {
      throw new StreamingUnsupportedError("Transformed streaming tool_calls must be a list.");
    }
    if (toolCalls.length > 0) {
      delta.tool_calls = toolCalls.map((call, order) => streamingToolCall(order, call)) as JsonValue;
    }
  }

  let finishReason = choice.finish_reason as JsonValue | undefined;
  if (finishReason === undefined || finishReason === null) {
    finishReason = toolCalls !== undefined && toolCalls !== null && Array.isArray(toolCalls) && toolCalls.length > 0 ? "tool_calls" : "stop";
  }

  const templateObject = isObject(template) ? template : {};
  const chunk: Record<string, JsonValue> = {};
  for (const key of PASSTHROUGH_CHUNK_KEYS) {
    if (Object.prototype.hasOwnProperty.call(templateObject, key)) {
      chunk[key] = templateObject[key] as JsonValue;
    }
  }
  chunk.object = CHUNK_OBJECT;
  chunk.choices = [{ index: 0, delta, finish_reason: finishReason }];
  return new TextEncoder().encode(`${sseFrame(JSON.stringify(chunk))}${sseFrame(DONE)}`);
}

async function collectStreamBytes(stream: StreamInput, limits: StreamingLimits): Promise<Uint8Array> {
  const maxBytes = maxStreamBytes(limits);
  const parts: Uint8Array[] = [];
  let total = 0;
  const append = (part: Uint8Array | ArrayBuffer | string) => {
    const bytes = rawToBytes(part);
    total += bytes.byteLength;
    if (total > maxBytes) {
      throw new StreamingUnsupportedError("Streaming response exceeded the buffering byte limit.");
    }
    parts.push(bytes);
  };

  if (typeof stream === "string" || stream instanceof Uint8Array || stream instanceof ArrayBuffer) {
    append(stream);
  } else if (isAsyncIterable(stream)) {
    for await (const part of stream) append(part);
  } else if (isIterable(stream)) {
    for (const part of stream) append(part);
  } else {
    throw new StreamingUnsupportedError("Streaming response must be bytes, text, or an iterable stream.");
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function parseSseChunks(raw: Uint8Array, limits: StreamingLimits): Array<Record<string, unknown>> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  } catch (cause) {
    throw new StreamingUnsupportedError("Streaming response contained malformed UTF-8.", { cause });
  }
  const chunks: Array<Record<string, unknown>> = [];
  let done = false;
  for (const block of text.split("\n\n")) {
    const data = eventData(block);
    if (data === undefined) continue;
    if (done) {
      throw new StreamingUnsupportedError("Streaming response sent data after [DONE].");
    }
    if (data === DONE) {
      done = true;
      continue;
    }
    if (chunks.length >= maxStreamEvents(limits)) {
      throw new StreamingUnsupportedError("Streaming response exceeded the buffered event limit.");
    }
    let chunk: unknown;
    try {
      chunk = JSON.parse(data);
    } catch (cause) {
      throw new StreamingUnsupportedError("Streaming response contained malformed SSE JSON.", { cause });
    }
    if (!isObject(chunk)) {
      throw new StreamingUnsupportedError("Streaming SSE chunk must be a JSON object.");
    }
    chunks.push(chunk);
  }
  if (!done) {
    throw new StreamingUnsupportedError("Streaming response terminated before [DONE].");
  }
  return chunks;
}

function streamingToolCall(order: number, call: unknown): JsonValue {
  if (!isObject(call)) {
    throw new StreamingUnsupportedError("Transformed streaming tool_call must be an object.");
  }
  const existing = (call as Record<string, unknown>).index;
  if (existing !== undefined && existing !== null && existing !== order) {
    throw new StreamingUnsupportedError("Transformed streaming tool_call index must match its order.");
  }
  return { ...(call as Record<string, JsonValue>), index: order };
}

function eventData(block: string): string | undefined {
  const lines = block.split("\n").filter((line) => line.length > 0 && !line.startsWith(COMMENT_PREFIX));
  const dataLines = lines
    .filter((line) => line.startsWith(DATA_FIELD))
    .map((line) => line.slice(DATA_FIELD.length).replace(/^ /, ""));
  return dataLines.length > 0 ? dataLines.join("\n") : undefined;
}

function mergeToolCallFragments(fragments: unknown, accumulators: Map<number, ToolCallAccumulator>): void {
  if (!fragments) return;
  if (!Array.isArray(fragments)) {
    throw new StreamingUnsupportedError("Streaming tool_calls must be a list.");
  }
  for (const fragment of fragments) {
    if (!isObject(fragment)) {
      throw new StreamingUnsupportedError("Streaming tool_call fragment must be an object.");
    }
    const index = fragment.index;
    if (!Number.isInteger(index)) {
      throw new StreamingUnsupportedError("Streaming tool_call fragments require an integer index.");
    }
    if (!accumulators.has(index as number)) {
      accumulators.set(index as number, new ToolCallAccumulator());
    }
    accumulators.get(index as number)?.merge(fragment);
  }
}

function mergeScalar(current: string | undefined, incoming: unknown): string | undefined {
  if (incoming === undefined || incoming === null) return current;
  if (typeof incoming !== "string") {
    throw new StreamingUnsupportedError("Streaming tool_call metadata must be strings.");
  }
  if (current !== undefined && current !== incoming) {
    throw new StreamingUnsupportedError("Streaming tool_call metadata changed mid-stream.");
  }
  return incoming;
}

function carriesUnrepresentedData(mapping: Record<string, unknown>, known: Set<string>): boolean {
  return Object.entries(mapping).some(([key, value]) => !known.has(key) && !isEmptyRepresentedValue(value));
}

function isEmptyRepresentedValue(value: unknown): boolean {
  return value === null || value === undefined || value === "" ||
    (Array.isArray(value) && value.length === 0) ||
    (isObject(value) && Object.keys(value).length === 0);
}

function sseFrame(data: string): string {
  return `data: ${data}\n\n`;
}

function rawToBytes(raw: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (typeof raw === "string") return new TextEncoder().encode(raw);
  if (raw instanceof Uint8Array) return raw;
  if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
  throw new StreamingUnsupportedError("Streaming response chunks must be bytes or strings.");
}

function failClosed(message: string, cause?: unknown): AgentControlBlockedError {
  const blocked = new AgentControlBlockedError(InterventionPoint.PostModelCall, {
    verdict: { decision: Decision.Deny, reason: "runtime_error:streaming_unsupported", message },
  });
  (blocked as { cause?: unknown }).cause = cause;
  return blocked;
}

function maxStreamBytes(limits: StreamingLimits): number {
  return limits.maxStreamBytes ?? DEFAULT_MAX_STREAM_BYTES;
}

function maxStreamEvents(limits: StreamingLimits): number {
  return limits.maxStreamEvents ?? DEFAULT_MAX_STREAM_EVENTS;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIterable(value: unknown): value is Iterable<Uint8Array | ArrayBuffer | string> {
  return typeof (value as { [Symbol.iterator]?: unknown })?.[Symbol.iterator] === "function";
}

function isAsyncIterable(value: unknown): value is AsyncIterable<Uint8Array | ArrayBuffer | string> {
  return typeof (value as { [Symbol.asyncIterator]?: unknown })?.[Symbol.asyncIterator] === "function";
}
