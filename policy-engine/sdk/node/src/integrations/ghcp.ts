import {
  Decision,
  EnforcementMode,
  InterventionPoint,
  InterventionPointResult,
  JsonValue,
} from "../index";
import type { AgentControl, ApprovalResolver } from "../index";
import { normalizeMode, transformedOr } from "../adapter-helpers";

const MAX_PENDING_TOOL_CALLS = 1024;
const SYNTHETIC_ID_PREFIX = "__acs_ghcp_synthetic__";

/**
 * How a tool call's id was determined for the snapshot. Surfaced to the logger
 * so live differences between the real CLI and the event stream are debuggable.
 * - `real-id`        the host supplied `toolCallId` directly (preferred); it is
 *                    carried into the snapshot.
 * - `event-bound`    matched a prior `assistant.message` tool request via onEvent;
 *                    that host id is carried into the snapshot.
 * - `synthetic`      no host id available; the snapshot omits `tool_call.id` and a
 *                    per-session monotonic id is minted for internal pre/post
 *                    correlation only (it never enters the snapshot).
 * - `post-fallback`  post-tool could not bind to a prior pre-tool admission and
 *                    evaluated from its own hook input instead; the snapshot
 *                    carries the host id when present and omits it otherwise.
 */
export type GhcpBindingMode = "real-id" | "event-bound" | "synthetic" | "post-fallback";

export interface GhcpLogEntry {
  hook: string;
  sessionId: string;
  interventionPoint: InterventionPoint;
  decision: Decision;
  reason?: string;
  toolName?: string;
  binding?: GhcpBindingMode;
}

export interface GhcpHooksOptions {
  mode?: EnforcementMode;
  snapshot?: Record<string, JsonValue>;
  approvalResolver?: ApprovalResolver;
  /**
   * How to surface an `escalate` verdict to the host when no `approvalResolver`
   * is configured. `"ask"` (default) returns Copilot's interactive permission
   * prompt; `"deny"` blocks (the historical fail-closed behavior). When an
   * `approvalResolver` IS configured it always takes precedence (ACS-verified
   * approval, including action-identity checks).
   */
  escalate?: "ask" | "deny";
  /**
   * Restrict which tools this guardrail evaluates. When set, tool calls whose
   * name is not governed are passed through untouched instead of being run
   * through a policy that may not be shaped for them (which would otherwise
   * fail closed, e.g. an LLM judge reading `$policy_target.command` on a
   * web-fetch tool that has no `command`). Omit to govern every tool.
   */
  tools?: string[] | ((toolName: string) => boolean);
  /** Optional sink for decision/runtime-error diagnostics. Never receives payloads. */
  logger?: (entry: GhcpLogEntry) => void;
}

export interface GhcpHookInvocation {
  sessionId?: string;
  [key: string]: unknown;
}

export interface GhcpSessionStartHookInput {
  [key: string]: unknown;
}

export interface GhcpUserPromptSubmittedHookInput {
  prompt?: string;
  [key: string]: unknown;
}

export interface GhcpPreToolUseHookInput {
  toolName?: string;
  toolArgs?: JsonValue;
  toolCallId?: string;
  [key: string]: unknown;
}

export interface GhcpPostToolUseHookInput extends GhcpPreToolUseHookInput {
  toolResult?: JsonValue;
}

export interface GhcpErrorOccurredHookInput {
  [key: string]: unknown;
}

export interface GhcpPermissionDecision {
  permissionDecision: "allow" | "deny" | "ask";
  permissionDecisionReason?: string;
}

export interface GhcpPromptDecision extends GhcpPermissionDecision {
  modifiedPrompt?: string;
  additionalContext?: string;
}

export interface GhcpToolResultDecision extends GhcpPermissionDecision {
  modifiedResult?: Record<string, JsonValue>;
}

export interface SessionHooks {
  onSessionStart?: (
    input?: GhcpSessionStartHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<GhcpPermissionDecision | undefined>;
  onUserPromptSubmitted?: (
    input: GhcpUserPromptSubmittedHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<GhcpPromptDecision | undefined>;
  onPreToolUse?: (
    input: GhcpPreToolUseHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<GhcpPermissionDecision | { modifiedArgs: JsonValue } | undefined>;
  onPostToolUse?: (
    input: GhcpPostToolUseHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<GhcpToolResultDecision | undefined>;
  onSessionEnd?: (
    input?: GhcpSessionStartHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<GhcpPermissionDecision | undefined>;
  onErrorOccurred?: (
    input?: GhcpErrorOccurredHookInput,
    invocation?: GhcpHookInvocation,
  ) => Promise<undefined>;
}

export interface GhcpExtension {
  hooks: SessionHooks;
  onEvent(event: unknown): void;
}

interface PendingEventToolCall {
  id: string;
  name: string;
  args: JsonValue;
  argsKey: string;
}

interface AdmittedToolCall {
  id: string;
  snapshotId: string | undefined;
  name: string;
  args: JsonValue;
  mode: GhcpBindingMode;
}

interface SessionState {
  messages?: JsonValue;
  toolRequests?: JsonValue;
}

export function createGhcpExtension(control: AgentControl, options: GhcpHooksOptions = {}): GhcpExtension {
  const mode = normalizeMode(options.mode ?? EnforcementMode.Enforce);
  const baseSnapshot = { ...(options.snapshot ?? {}) };
  const pendingBySession = new Map<string, PendingEventToolCall[]>();
  const admittedBySession = new Map<string, AdmittedToolCall[]>();
  const stateBySession = new Map<string, SessionState>();
  const syntheticCounterBySession = new Map<string, number>();
  let pendingToolCallCount = 0;

  const escalateBehavior = options.escalate ?? "ask";
  const governs = toolGovernancePredicate(options.tools);

  function log(entry: GhcpLogEntry): void {
    if (options.logger === undefined) return;
    try {
      options.logger(entry);
    } catch {
      // A faulty logger must never affect enforcement.
    }
  }

  function syntheticId(sessionId: string): string {
    const next = (syntheticCounterBySession.get(sessionId) ?? 0) + 1;
    syntheticCounterBySession.set(sessionId, next);
    return `${SYNTHETIC_ID_PREFIX}:${sessionId}:${next}`;
  }

  function ghcpToolCall(id: string | undefined, name: string, args: JsonValue): Record<string, JsonValue> {
    const toolCall: Record<string, JsonValue> = { name, args };
    if (id !== undefined) toolCall.id = id;
    return toolCall;
  }

  /**
   * Map a verdict to a host gate outcome. Returns `undefined` to allow (also
   * for `warn`, which is non-blocking). Effects are applied separately by the
   * caller via {@link transformedOr}.
   */
  async function gate(
    interventionPoint: InterventionPoint,
    sessionId: string,
    hook: string,
    result: InterventionPointResult,
    toolName?: string,
    binding?: GhcpBindingMode,
  ): Promise<{ deny: string } | { ask: string } | undefined> {
    if (mode !== EnforcementMode.Enforce) return undefined;
    const decision = result.verdict.decision;
    const reason = result.verdict.reason ?? result.verdict.message ?? undefined;

    if (decision === Decision.Deny) {
      log({ hook, sessionId, interventionPoint, decision, reason, toolName, binding });
      return { deny: denialMessage(result) };
    }
    if (decision === Decision.Escalate) {
      const resolver = options.approvalResolver;
      if (resolver !== undefined) {
        try {
          await control.enforce(interventionPoint, result, mode, resolver);
          return undefined;
        } catch {
          log({ hook, sessionId, interventionPoint, decision: Decision.Deny, reason, toolName, binding });
          return { deny: denialMessage(result) };
        }
      }
      log({ hook, sessionId, interventionPoint, decision, reason, toolName, binding });
      if (escalateBehavior === "deny") return { deny: denialMessage(result) };
      return { ask: denialMessage(result) };
    }
    return undefined;
  }

  async function evaluate(
    interventionPoint: InterventionPoint,
    sessionId: string,
    hook: string,
    invocation: GhcpHookInvocation,
    hookInput: unknown,
    snapshot: Record<string, JsonValue>,
  ): Promise<InterventionPointResult> {
    captureSessionState(sessionId, hookInput);
    return await control.evaluateInterventionPoint(
      interventionPoint,
      buildSnapshot(sessionId, hook, invocation, snapshot),
      mode,
    );
  }

  const extension: GhcpExtension = {
    onEvent(event: unknown) {
      const eventObject = isUnknownRecord(event) ? event : {};
      const data = isUnknownRecord(eventObject.data) ? eventObject.data : {};
      const sessionId = sessionKey({
        sessionId: stringFromUnknown(eventObject.sessionId) ?? stringFromUnknown(data.sessionId),
      });
      captureSessionState(sessionId, event);
      if (eventObject.type !== "assistant.message") return;
      const requests = Array.isArray(data.toolRequests) ? data.toolRequests : [];
      if (requests.length === 0) return;
      const serializedRequests = asJsonValue(requests);
      if (serializedRequests !== undefined) {
        sessionState(sessionId).toolRequests = serializedRequests;
      }
      let queue = pendingBySession.get(sessionId);
      if (queue === undefined) {
        queue = [];
        pendingBySession.set(sessionId, queue);
      }
      for (const request of requests) {
        const record = isUnknownRecord(request) ? request : {};
        const id = stringFromUnknown(record.toolCallId) ?? stringFromUnknown(record.id);
        const name = stringFromUnknown(record.name) ?? stringFromUnknown(record.toolName);
        if (id === undefined || name === undefined) continue;
        const args = asJsonValue(record.arguments ?? record.args ?? {}) ?? {};
        queue.push({ id, name, args, argsKey: toolKey(name, args) });
        pendingToolCallCount += 1;
      }
      trimPendingQueues();
    },

    hooks: {
      async onSessionStart(input = {}, invocation = {}) {
        const sessionId = sessionKey(invocation);
        const result = await evaluate(
          InterventionPoint.AgentStartup,
          sessionId,
          "onSessionStart",
          invocation,
          input,
          {},
        );
        return toPermission(await gate(InterventionPoint.AgentStartup, sessionId, "onSessionStart", result));
      },

      async onUserPromptSubmitted(input, invocation = {}) {
        const sessionId = sessionKey(invocation);
        const prompt = input.prompt ?? "";
        const result = await evaluate(
          InterventionPoint.Input,
          sessionId,
          "onUserPromptSubmitted",
          invocation,
          input,
          { input: prompt },
        );
        // A prompt cannot be "asked about"; both deny and escalate become a refusal.
        const g = await gate(InterventionPoint.Input, sessionId, "onUserPromptSubmitted", result);
        if (g !== undefined) {
          return {
            permissionDecision: "deny",
            permissionDecisionReason: "deny" in g ? g.deny : g.ask,
            modifiedPrompt: denialMessage(result),
            additionalContext: denialMessage(result),
          };
        }
        const effectivePrompt = transformedOr(result, prompt, mode);
        if (effectivePrompt !== prompt) return { permissionDecision: "allow", modifiedPrompt: stringifyPrompt(effectivePrompt) };
        return undefined;
      },

      async onPreToolUse(input, invocation = {}) {
        const sessionId = sessionKey(invocation);
        const toolName = input.toolName ?? "";
        if (!governs(toolName)) {
          log({ hook: "onPreToolUse", sessionId, interventionPoint: InterventionPoint.PreToolCall, decision: Decision.Allow, reason: "tool not governed; passed through", toolName });
          return undefined;
        }
        const args = asObject(input.toolArgs ?? {});
        const bound = bindPre(sessionId, toolName, args, stringFromUnknown(input.toolCallId));
        const result = await evaluate(
          InterventionPoint.PreToolCall,
          sessionId,
          "onPreToolUse",
          invocation,
          input,
          { tool_call: ghcpToolCall(bound.snapshotId, toolName, args) },
        );
        const g = await gate(InterventionPoint.PreToolCall, sessionId, "onPreToolUse", result, toolName, bound.mode);
        if (g !== undefined) return toPermission(g)!;
        const effectiveArgs = transformedOr(result, args, mode);
        rememberAdmitted(sessionId, { id: bound.correlationId, snapshotId: bound.snapshotId, name: toolName, args: effectiveArgs, mode: bound.mode });
        if (effectiveArgs !== args) return { modifiedArgs: effectiveArgs };
        return undefined;
      },

      async onPostToolUse(input, invocation = {}) {
        const sessionId = sessionKey(invocation);
        const toolName = input.toolName ?? "";
        if (!governs(toolName)) {
          log({ hook: "onPostToolUse", sessionId, interventionPoint: InterventionPoint.PostToolCall, decision: Decision.Allow, reason: "tool not governed; passed through", toolName });
          return undefined;
        }
        const bound = bindPost(sessionId, toolName, stringFromUnknown(input.toolCallId));
        // Prefer the admitted (possibly transformed) args; fall back to the hook's own.
        const args = bound.args ?? asObject(input.toolArgs ?? {});
        const toolResult = asObject(input.toolResult ?? null);
        const result = await evaluate(
          InterventionPoint.PostToolCall,
          sessionId,
          "onPostToolUse",
          invocation,
          input,
          {
            tool_call: ghcpToolCall(bound.snapshotId, bound.name, args),
            tool_result: toolResult,
          },
        );
        const g = await gate(InterventionPoint.PostToolCall, sessionId, "onPostToolUse", result, toolName, bound.mode);
        // A produced result cannot be "asked about"; deny or escalate reject it.
        if (g !== undefined) return rejectedToolResult("deny" in g ? g.deny : g.ask);
        const effectiveResult = transformedOr(result, toolResult, mode);
        if (effectiveResult !== toolResult) return { permissionDecision: "allow", modifiedResult: toolResultObject(effectiveResult) };
        return undefined;
      },

      async onSessionEnd(input = {}, invocation = {}) {
        const sessionId = sessionKey(invocation);
        const result = await evaluate(
          InterventionPoint.AgentShutdown,
          sessionId,
          "onSessionEnd",
          invocation,
          input,
          {},
        );
        pendingToolCallCount -= pendingBySession.get(sessionId)?.length ?? 0;
        pendingBySession.delete(sessionId);
        admittedBySession.delete(sessionId);
        stateBySession.delete(sessionId);
        syntheticCounterBySession.delete(sessionId);
        return toPermission(await gate(InterventionPoint.AgentShutdown, sessionId, "onSessionEnd", result));
      },

      async onErrorOccurred(input = {}, invocation = {}) {
        captureSessionState(sessionKey(invocation), input);
        return undefined;
      },
    },
  };

  return extension;

  function buildSnapshot(
    sessionId: string,
    hook: string,
    invocation: GhcpHookInvocation,
    snapshot: Record<string, JsonValue>,
  ): Record<string, JsonValue> {
    const state = stateBySession.get(sessionId) ?? {};
    const captured: Record<string, JsonValue> = {};
    if (state.messages !== undefined) {
      captured.messages = state.messages;
      captured.model_request = { messages: state.messages };
    }
    if (state.toolRequests !== undefined) captured.tool_requests = state.toolRequests;
    return {
      ...baseSnapshot,
      ...captured,
      ...snapshot,
      ghcp: {
        hook,
        invocation: invocationSnapshot(invocation),
      },
    };
  }

  function captureSessionState(sessionId: string, value: unknown): void {
    const messages = findMessages(value);
    if (messages !== undefined) sessionState(sessionId).messages = messages;
  }

  function sessionState(sessionId: string): SessionState {
    let state = stateBySession.get(sessionId);
    if (state === undefined) {
      state = {};
      stateBySession.set(sessionId, state);
    }
    return state;
  }

  function rememberAdmitted(sessionId: string, toolCall: AdmittedToolCall): void {
    const queue = admittedBySession.get(sessionId) ?? [];
    queue.push(toolCall);
    admittedBySession.set(sessionId, queue);
  }

  // Best-effort pre-tool binding: real host id > event-bound id > synthesized.
  // Never fails. `snapshotId` is the host id when one exists and undefined when
  // it does not (the snapshot then omits tool_call.id). `correlationId` is always
  // present and is used only for internal pre/post admission matching.
  function bindPre(
    sessionId: string,
    toolName: string,
    args: JsonValue,
    toolCallId: string | undefined,
  ): { correlationId: string; snapshotId: string | undefined; mode: GhcpBindingMode } {
    if (toolCallId !== undefined) return { correlationId: toolCallId, snapshotId: toolCallId, mode: "real-id" };
    const match = popPending(sessionId, toolName, args);
    if (match !== null && match.ambiguous === false) return { correlationId: match.id, snapshotId: match.id, mode: "event-bound" };
    return { correlationId: syntheticId(sessionId), snapshotId: undefined, mode: "synthetic" };
  }

  // Best-effort post-tool binding: real id > FIFO same-name admission > fallback
  // to the hook's own input. Never rejects purely because binding failed.
  // `snapshotId` carries the host id when one exists and is undefined otherwise.
  function bindPost(
    sessionId: string,
    toolName: string,
    toolCallId: string | undefined,
  ): { snapshotId: string | undefined; name: string; args?: JsonValue; mode: GhcpBindingMode } {
    if (toolCallId !== undefined) {
      const byId = popAdmittedById(sessionId, toolCallId);
      if (byId !== undefined) return { snapshotId: byId.snapshotId, name: byId.name, args: byId.args, mode: byId.mode };
    }
    const byName = popAdmitted(sessionId, toolName);
    if (byName !== undefined) return { snapshotId: byName.snapshotId, name: byName.name, args: byName.args, mode: byName.mode };
    log({ hook: "onPostToolUse", sessionId, interventionPoint: InterventionPoint.PostToolCall, decision: Decision.Allow, reason: "no prior admission; evaluated from post-tool input", toolName, binding: "post-fallback" });
    return { snapshotId: toolCallId, name: toolName, mode: "post-fallback" };
  }

  // FIFO first match by tool name; the queue preserves admission order.
  function popAdmitted(sessionId: string, toolName: string): AdmittedToolCall | undefined {
    const queue = admittedBySession.get(sessionId);
    if (queue === undefined) return undefined;
    const index = queue.findIndex((item) => item.name === toolName);
    if (index === -1) return undefined;
    if (queue.filter((item) => item.name === toolName).length > 1) {
      log({ hook: "onPostToolUse", sessionId, interventionPoint: InterventionPoint.PostToolCall, decision: Decision.Allow, reason: "multiple in-flight calls to the same tool; bound FIFO", toolName });
    }
    const [entry] = queue.splice(index, 1);
    return entry;
  }

  function popAdmittedById(sessionId: string, toolCallId: string): AdmittedToolCall | undefined {
    const queue = admittedBySession.get(sessionId);
    if (queue === undefined) return undefined;
    const index = queue.findIndex((item) => item.id === toolCallId);
    if (index === -1) return undefined;
    const [entry] = queue.splice(index, 1);
    return entry;
  }

  function popPending(sessionId: string, toolName: string, args: JsonValue): { id: string; ambiguous: false } | { ambiguous: true } | null {
    const queue = pendingBySession.get(sessionId);
    if (queue === undefined) return null;
    const key = toolKey(toolName, args);
    const matches = queue.map((item, index) => ({ item, index })).filter(({ item }) => item.argsKey === key);
    if (matches.length === 0) return null;
    if (matches.length !== 1) return { ambiguous: true };
    const entry = matches[0];
    queue.splice(entry.index, 1);
    pendingToolCallCount -= 1;
    return { id: entry.item.id, ambiguous: false };
  }

  function trimPendingQueues(): void {
    if (pendingToolCallCount <= MAX_PENDING_TOOL_CALLS) return;
    pendingBySession.clear();
    pendingToolCallCount = 0;
  }
}

export function createGhcpHooks(control: AgentControl, options: GhcpHooksOptions = {}): SessionHooks {
  return createGhcpExtension(control, options).hooks;
}

function toPermission(
  gateResult: { deny: string } | { ask: string } | undefined,
): GhcpPermissionDecision | undefined {
  if (gateResult === undefined) return undefined;
  if ("deny" in gateResult) return { permissionDecision: "deny", permissionDecisionReason: gateResult.deny };
  return { permissionDecision: "ask", permissionDecisionReason: gateResult.ask };
}

function toolGovernancePredicate(tools: GhcpHooksOptions["tools"]): (toolName: string) => boolean {
  if (tools === undefined) return () => true;
  if (typeof tools === "function") return tools;
  const allowed = new Set(tools);
  return (toolName: string) => allowed.has(toolName);
}

// The CLI may hand tool args/results as a JSON-encoded string rather than an
// object. Parse those so object-shaped policy targets resolve; pass through
// anything that isn't a parseable string unchanged (the policy then decides).
function asObject(value: JsonValue): JsonValue {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as JsonValue;
  } catch {
    return value;
  }
}

function rejectedToolResult(message: string): GhcpToolResultDecision {
  return {
    permissionDecision: "deny",
    permissionDecisionReason: message,
    modifiedResult: { textResultForLlm: message, resultType: "rejected" },
  };
}

function denialMessage(result: InterventionPointResult): string {
  return result.verdict.message ?? result.verdict.reason ?? "blocked by policy";
}

function stringifyPrompt(value: JsonValue): string {
  return typeof value === "string" ? value : JSON.stringify(value) ?? "null";
}

function toolResultObject(value: JsonValue): Record<string, JsonValue> {
  if (isJsonRecord(value)) return value;
  return { textResultForLlm: stringifyPrompt(value), resultType: "success" };
}

function invocationSnapshot(invocation: GhcpHookInvocation): Record<string, JsonValue> {
  const snapshot: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(invocation)) {
    const json = asJsonValue(value);
    if (json !== undefined) snapshot[key] = json;
  }
  return snapshot;
}

function sessionKey(invocation: GhcpHookInvocation): string {
  return invocation.sessionId ?? "__acs_ghcp_default_session__";
}

function toolKey(toolName: string, args: JsonValue): string {
  return `${toolName}\u0000${canonicalJson(args)}`;
}

function canonicalJson(value: JsonValue): string {
  return JSON.stringify(value, (_key, item) => {
    if (isJsonRecord(item)) {
      return Object.keys(item)
        .sort()
        .reduce<Record<string, JsonValue>>((acc, key) => {
          acc[key] = item[key];
          return acc;
        }, {});
    }
    return item;
  });
}

function findMessages(value: unknown, depth = 0): JsonValue | undefined {
  if (depth > 3 || !isUnknownRecord(value)) return undefined;
  const direct = asJsonValue(value.messages);
  if (Array.isArray(direct)) return direct;
  for (const key of ["conversation", "conversationHistory", "messageHistory", "request", "data"]) {
    const nested = findMessages(value[key], depth + 1);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

function asJsonValue(value: unknown): JsonValue | undefined {
  if (value === undefined || typeof value === "function" || typeof value === "symbol") return undefined;
  try {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) return undefined;
    return JSON.parse(serialized) as JsonValue;
  } catch {
    return String(value);
  }
}

function stringFromUnknown(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function isUnknownRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonRecord(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
