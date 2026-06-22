import { createHash } from "node:crypto";
import * as native from "../native.js";
import {
  AgentControlBlockedError,
  AgentControlInterruptionError,
  AgentControlSuspendedError,
  transformedOr,
} from "./adapter-helpers";
import { configureOpaPath } from "./integrations/opa-binary";

export { AgentControlBlockedError, AgentControlInterruptionError, AgentControlSuspendedError };

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export const InterventionPoint = Object.freeze({
  AgentStartup: "agent_startup",
  Input: "input",
  PreModelCall: "pre_model_call",
  PostModelCall: "post_model_call",
  PreToolCall: "pre_tool_call",
  PostToolCall: "post_tool_call",
  Output: "output",
  AgentShutdown: "agent_shutdown",
} as const);
export type InterventionPoint = (typeof InterventionPoint)[keyof typeof InterventionPoint];

export const EnforcementMode = Object.freeze({
  Enforce: "enforce",
  EvaluateOnly: "evaluate_only",
} as const);
export type EnforcementMode = (typeof EnforcementMode)[keyof typeof EnforcementMode];

export const Decision = Object.freeze({
  Allow: "allow",
  Deny: "deny",
  Warn: "warn",
  Escalate: "escalate",
  Transform: "transform",
} as const);
export type Decision = (typeof Decision)[keyof typeof Decision];

export const PerfTelemetry = Object.freeze({
  Off: 0,
  External: 1,
  Full: 2,
} as const);
export type PerfTelemetry = (typeof PerfTelemetry)[keyof typeof PerfTelemetry];

export const ApprovalOutcome = Object.freeze({
  Allow: "allow",
  Deny: "deny",
  Suspend: "suspend",
} as const);
export type ApprovalOutcome = (typeof ApprovalOutcome)[keyof typeof ApprovalOutcome];

export interface ApprovalResolution {
  outcome: ApprovalOutcome;
  handle?: JsonValue;
  actionIdentity?: string;
}

export const ApprovalResolution = Object.freeze({
  allow(actionIdentity: string): ApprovalResolution {
    return { outcome: ApprovalOutcome.Allow, actionIdentity };
  },
  deny(): ApprovalResolution {
    return { outcome: ApprovalOutcome.Deny };
  },
  suspend(handle: JsonValue | undefined, actionIdentity: string): ApprovalResolution {
    return { outcome: ApprovalOutcome.Suspend, handle, actionIdentity };
  },
});

export type ApprovalResolver = (
  interventionPoint: InterventionPoint,
  result: InterventionPointResult,
) => Promise<ApprovalResolution> | ApprovalResolution;

/**
 * AGT D1.1 single-target replacement payload that mirrors
 * `core/src/verdict.rs::Transform`. The runtime applies `value` at
 * `path` (rooted at `$policy_target`) before propagating the result.
 */
export interface Transform {
  path: string;
  value: JsonValue;
}

/**
 * AGT D2 opaque evidence payload propagated verbatim from the
 * dispatcher. `artefact` is a content address (typically
 * `sha256:<hex>`) of an offline-verifiable proof; `verificationPointers`
 * maps named pointer keys to URLs that an auditor MAY consult to
 * re-verify the decision. The SDK does not validate or fetch either
 * field; AGT-EVIDENCE-1.0 §3 restricts telemetry to the artefact and
 * sorted pointer keys, while §4 keeps the full pointer map in the
 * audit record.
 */
export interface Evidence {
  artefact?: string;
  verificationPointers?: Record<string, string>;
}

export interface Verdict {
  decision: Decision;
  reason?: string | null;
  message?: string | null;
  /** AGT D1.1 single-target replacement payload. Present only when
   * `decision === 'transform'`; forbidden on every other decision. */
  transform?: Transform;
  /** AGT D2 opaque evidence payload. Propagated verbatim by the
   * runtime; the SDK performs no semantic validation on it. */
  evidence?: Evidence;
  result_labels?: string[];
}

export interface InterventionPointRequest {
  interventionPoint: InterventionPoint;
  snapshot: JsonValue;
  mode?: EnforcementMode;
}

export interface InterventionPointResult {
  verdict: Verdict;
  transformedPolicyTarget?: JsonValue;
  transformedPolicyTargetApplied?: boolean;
  policyInput?: JsonValue;
  /** AGT D1.4 SHA-256 of the canonical policy input that was
   * evaluated. Pins what the policy actually saw. */
  inputIdentity?: string;
  /** AGT D1.4 SHA-256 of the canonical policy input AFTER the
   * transform path is applied to the policy target. Equal to
   * `inputIdentity` for every non-transform decision. Pins what the
   * host actually carried out. */
  enforcedIdentity?: string;
  /** Backwards-compatible alias for `enforcedIdentity` per AGT D1.4;
   * pre-bisection callers MAY default to this single-identity slot.
   * Mirrors the action_identity field on InterventionPointResult in
   * core/src/runtime.rs. */
  actionIdentity?: string;
}

export interface RunResult<T = JsonValue> {
  value: T;
  inputResult: InterventionPointResult;
  outputResult: InterventionPointResult;
}

export interface ToolRunResult<T = JsonValue> {
  value: T;
  preToolCallResult: InterventionPointResult;
  postToolCallResult: InterventionPointResult;
}

export interface AnnotatorDispatcher {
  dispatch(
    annotatorName: string,
    annotatorConfig: Record<string, JsonValue>,
    preliminaryPolicyInput: JsonValue,
  ): Promise<JsonValue> | JsonValue;
}

export interface PolicyDispatcher {
  evaluate(invocation: Record<string, JsonValue>): Promise<Record<string, JsonValue>> | Record<string, JsonValue>;
}

export interface RuntimeClient {
  evaluateInterventionPoint(request: InterventionPointRequest): Promise<InterventionPointResult>;
}

type NativeRuntime = {
  evaluate(request: Record<string, JsonValue>): Promise<Record<string, JsonValue>>;
};

type NativeRuntimeCallback = (err: Error | null, argsJson: string) => Promise<string>;

type NativeRuntimeConstructor = {
  new (
    manifest: string,
    annotatorCallback: NativeRuntimeCallback | undefined,
    policyCallback: NativeRuntimeCallback | undefined,
    perfTelemetry?: PerfTelemetry,
  ): NativeRuntime;
  fromPath(
    path: string,
    annotatorCallback: NativeRuntimeCallback | undefined,
    policyCallback: NativeRuntimeCallback | undefined,
    perfTelemetry?: PerfTelemetry,
  ): NativeRuntime;
  fromUrl(
    url: string,
    sha256: string | undefined | null,
    annotatorCallback: NativeRuntimeCallback | undefined,
    policyCallback: NativeRuntimeCallback | undefined,
    perfTelemetry?: PerfTelemetry,
    maxUrlBytes?: number,
    urlTimeoutMs?: number,
    maxUrlRedirects?: number,
  ): NativeRuntime;
  fromManifestChain(
    manifests: string[],
    annotatorCallback: NativeRuntimeCallback | undefined,
    policyCallback: NativeRuntimeCallback | undefined,
    perfTelemetry?: PerfTelemetry,
  ): NativeRuntime;
};

type NativeRuntimeLoader = (
  nativeRuntimeClass: NativeRuntimeConstructor,
  annotatorCallback: NativeRuntimeCallback | undefined,
  policyCallback: NativeRuntimeCallback | undefined,
) => NativeRuntime;

export class NativeRuntimeClient implements RuntimeClient {
  private readonly runtime: NativeRuntime;
  private readonly annotatorDispatcher: AnnotatorDispatcher | undefined;
  private readonly policyDispatcher: PolicyDispatcher | undefined;

  constructor(
    manifest: JsonValue | string,
    annotatorDispatcher?: AnnotatorDispatcher,
    policyDispatcher?: PolicyDispatcher,
    perfTelemetry: PerfTelemetry = PerfTelemetry.Off,
    loader?: NativeRuntimeLoader,
  ) {
    this.annotatorDispatcher = annotatorDispatcher;
    this.policyDispatcher = policyDispatcher;
    if (policyDispatcher === undefined) configureOpaPath();
    const manifestString = typeof manifest === "string" ? manifest : JSON.stringify(manifest);
    const NativeRuntimeClass = (native as { NativeRuntime: NativeRuntimeConstructor }).NativeRuntime;
    // An undefined dispatcher opts into the bundled native default (OPA policy /
    // classifier annotator) supplied by the Rust core.
    const annotatorCallback: NativeRuntimeCallback | undefined = annotatorDispatcher
      ? async (err, argsJson) => {
        if (err) throw err;
        const envelope = JSON.parse(argsJson) as {
          annotator_name: string;
          annotator: Record<string, JsonValue>;
          preliminary_policy_input: JsonValue;
        };
        const result = await annotatorDispatcher.dispatch(
          envelope.annotator_name,
          envelope.annotator,
          envelope.preliminary_policy_input,
        );
        return JSON.stringify(result);
      }
      : undefined;
    const policyCallback: NativeRuntimeCallback | undefined = policyDispatcher
      ? async (err, argsJson) => {
        if (err) throw err;
        const envelope = JSON.parse(argsJson) as { invocation: Record<string, JsonValue> };
        const result = await policyDispatcher.evaluate(envelope.invocation);
        return JSON.stringify(result);
      }
      : undefined;
    this.runtime = loader
      ? loader(NativeRuntimeClass, annotatorCallback, policyCallback)
      : new NativeRuntimeClass(manifestString, annotatorCallback, policyCallback, perfTelemetry);
  }

  async evaluateInterventionPoint(request: InterventionPointRequest): Promise<InterventionPointResult> {
    const raw = await this.runtime.evaluate({
      intervention_point: request.interventionPoint,
      snapshot: request.snapshot,
      mode: request.mode ?? EnforcementMode.Enforce,
    });
    return mapResult(raw);
  }
}

export class AgentControl {
  private readonly runtimeClient: RuntimeClient;
  private readonly approvalResolver: ApprovalResolver | undefined;

  constructor(runtimeClient: RuntimeClient, approvalResolver?: ApprovalResolver) {
    this.runtimeClient = runtimeClient;
    this.approvalResolver = approvalResolver;
  }

  static fromNative(
    manifest: JsonValue | string,
    annotatorDispatcher?: AnnotatorDispatcher,
    policyDispatcher?: PolicyDispatcher,
    approvalResolver?: ApprovalResolver,
    perfTelemetry: PerfTelemetry = PerfTelemetry.Off,
  ): AgentControl {
    return new AgentControl(
      new NativeRuntimeClient(manifest, annotatorDispatcher, policyDispatcher, perfTelemetry),
      approvalResolver,
    );
  }

  static fromPath(
    path: string,
    annotatorDispatcher?: AnnotatorDispatcher,
    policyDispatcher?: PolicyDispatcher,
    approvalResolver?: ApprovalResolver,
    perfTelemetry: PerfTelemetry = PerfTelemetry.Off,
  ): AgentControl {
    return new AgentControl(
      new NativeRuntimeClient(path, annotatorDispatcher, policyDispatcher, perfTelemetry, (NativeRuntimeClass, annotator, policy) =>
        NativeRuntimeClass.fromPath(path, annotator, policy, perfTelemetry),
      ),
      approvalResolver,
    );
  }

  static fromUrl(
    url: string,
    sha256?: string,
    annotatorDispatcher?: AnnotatorDispatcher,
    policyDispatcher?: PolicyDispatcher,
    approvalResolver?: ApprovalResolver,
    perfTelemetry: PerfTelemetry = PerfTelemetry.Off,
    urlFetchLimits?: {
      maxBytes?: number;
      timeoutMs?: number;
      maxRedirects?: number;
    },
  ): AgentControl {
    return new AgentControl(
      new NativeRuntimeClient(url, annotatorDispatcher, policyDispatcher, perfTelemetry, (NativeRuntimeClass, annotator, policy) =>
        NativeRuntimeClass.fromUrl(
          url,
          sha256,
          annotator,
          policy,
          perfTelemetry,
          urlFetchLimits?.maxBytes,
          urlFetchLimits?.timeoutMs,
          urlFetchLimits?.maxRedirects,
        ),
      ),
      approvalResolver,
    );
  }

  static fromManifestChain(
    manifests: string[],
    annotatorDispatcher?: AnnotatorDispatcher,
    policyDispatcher?: PolicyDispatcher,
    approvalResolver?: ApprovalResolver,
    perfTelemetry: PerfTelemetry = PerfTelemetry.Off,
  ): AgentControl {
    return new AgentControl(
      new NativeRuntimeClient("", annotatorDispatcher, policyDispatcher, perfTelemetry, (NativeRuntimeClass, annotator, policy) =>
        NativeRuntimeClass.fromManifestChain(manifests, annotator, policy, perfTelemetry),
      ),
      approvalResolver,
    );
  }

  async evaluateInterventionPoint(
    interventionPoint: InterventionPoint,
    snapshot: Record<string, JsonValue>,
    mode: EnforcementMode = EnforcementMode.Enforce,
  ): Promise<InterventionPointResult> {
    return this.runtimeClient.evaluateInterventionPoint({ interventionPoint, snapshot, mode });
  }

  async enforce(
    interventionPoint: InterventionPoint,
    result: InterventionPointResult,
    mode: EnforcementMode = EnforcementMode.Enforce,
    approvalResolver?: ApprovalResolver,
  ): Promise<void> {
    if (mode !== EnforcementMode.Enforce) return;
    const decision = result.verdict.decision;
    if (decision === Decision.Deny) {
      throw new AgentControlBlockedError(interventionPoint, result);
    }
    if (decision !== Decision.Escalate) return;

    const resolver = approvalResolver ?? this.approvalResolver;
    if (resolver === undefined) {
      throw new AgentControlBlockedError(interventionPoint, result);
    }

    const originalIdentity = result.actionIdentity;
    let resolution: ApprovalResolution;
    try {
      resolution = await resolver(interventionPoint, result);
    } catch (error) {
      const blocked = new AgentControlBlockedError(interventionPoint, approvalResolverFailedResult(result));
      (blocked as { cause?: unknown }).cause = error;
      throw blocked;
    }

    if (resolution === undefined || resolution === null) {
      throw new AgentControlBlockedError(interventionPoint, approvalResolverFailedResult(result));
    }

    switch (resolution.outcome) {
      case ApprovalOutcome.Allow:
        requireApprovedIdentity(interventionPoint, result, originalIdentity, resolution.actionIdentity);
        return;
      case ApprovalOutcome.Suspend:
        requireApprovedIdentity(interventionPoint, result, originalIdentity, resolution.actionIdentity);
        throw new AgentControlSuspendedError(interventionPoint, result, resolution.handle);
      case ApprovalOutcome.Deny:
        throw new AgentControlBlockedError(interventionPoint, result);
      default:
        throw new AgentControlBlockedError(interventionPoint, approvalResolverFailedResult(result));
    }
  }

  async run<TInput extends JsonValue, TOutput extends JsonValue>(
    input: TInput,
    execute: (input: JsonValue) => Promise<TOutput> | TOutput,
    options: {
      snapshot?: Record<string, JsonValue>;
      mode?: EnforcementMode;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): Promise<RunResult<JsonValue>> {
    const mode = options.mode ?? EnforcementMode.Enforce;
    const resolver = options.approvalResolver;
    const ambient = { ...(options.snapshot ?? {}) };
    const inputResult = await this.evaluateInterventionPoint(
      InterventionPoint.Input,
      { ...ambient, input },
      mode,
    );
    await this.enforce(InterventionPoint.Input, inputResult, mode, resolver);
    const effectiveInput = transformedOr(inputResult, input, mode);
    const output = await execute(effectiveInput);
    const outputResult = await this.evaluateInterventionPoint(
      InterventionPoint.Output,
      { ...ambient, input: effectiveInput, output },
      mode,
    );
    await this.enforce(InterventionPoint.Output, outputResult, mode, resolver);
    return { value: transformedOr(outputResult, output, mode), inputResult, outputResult };
  }

  protectTool(
    toolName: string,
    execute: (args: JsonValue) => Promise<JsonValue> | JsonValue,
    options: {
      mode?: EnforcementMode;
      snapshot?: Record<string, JsonValue>;
      toolCallId?: string;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): (
    args: JsonValue,
    callOptions?: { toolCallId?: string; snapshot?: Record<string, JsonValue>; approvalResolver?: ApprovalResolver },
  ) => Promise<ToolRunResult<JsonValue>> {
    const defaultSnapshot = { ...(options.snapshot ?? {}) };
    return async (args, callOptions = {}) => {
      const snapshot = { ...defaultSnapshot, ...(callOptions.snapshot ?? {}) };
      return this.runTool(toolName, args, execute, {
        toolCallId: callOptions.toolCallId ?? options.toolCallId,
        snapshot,
        mode: options.mode,
        approvalResolver: callOptions.approvalResolver ?? options.approvalResolver,
      });
    };
  }

  async runTool(
    toolName: string,
    args: JsonValue,
    execute: (args: JsonValue) => Promise<JsonValue> | JsonValue,
    options: {
      toolCallId?: string;
      snapshot?: Record<string, JsonValue>;
      mode?: EnforcementMode;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): Promise<ToolRunResult<JsonValue>> {
    const mode = options.mode ?? EnforcementMode.Enforce;
    const resolver = options.approvalResolver;
    const ambient = { ...(options.snapshot ?? {}) };
    const toolCallId = normalizeToolCallId(options.toolCallId);
    const toolCall = makeToolCall(toolName, args, toolCallId);
    const preToolCallResult = await this.evaluateInterventionPoint(
      InterventionPoint.PreToolCall,
      { ...ambient, tool_call: toolCall },
      mode,
    );
    await this.enforce(InterventionPoint.PreToolCall, preToolCallResult, mode, resolver);
    const effectiveArgs = transformedOr(preToolCallResult, args, mode);
    const toolResult = await execute(effectiveArgs);
    const postToolCallResult = await this.evaluateInterventionPoint(
      InterventionPoint.PostToolCall,
      {
        ...ambient,
        tool_call: makeToolCall(toolName, effectiveArgs, toolCallId),
        tool_result: toolResult,
      },
      mode,
    );
    await this.enforce(InterventionPoint.PostToolCall, postToolCallResult, mode, resolver);
    return {
      value: transformedOr(postToolCallResult, toolResult, mode),
      preToolCallResult,
      postToolCallResult,
    };
  }

  async agentStartup(
    agent: JsonValue,
    options: {
      snapshot?: Record<string, JsonValue>;
      mode?: EnforcementMode;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): Promise<InterventionPointResult> {
    const mode = options.mode ?? EnforcementMode.Enforce;
    const resolver = options.approvalResolver;
    const ambient = { ...(options.snapshot ?? {}) };
    const result = await this.evaluateInterventionPoint(
      InterventionPoint.AgentStartup,
      { ...ambient, agent },
      mode,
    );
    await this.enforce(InterventionPoint.AgentStartup, result, mode, resolver);
    return result;
  }

  async agentShutdown(
    summary: JsonValue,
    options: {
      snapshot?: Record<string, JsonValue>;
      mode?: EnforcementMode;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): Promise<InterventionPointResult> {
    const mode = options.mode ?? EnforcementMode.Enforce;
    const resolver = options.approvalResolver;
    const ambient = { ...(options.snapshot ?? {}) };
    const result = await this.evaluateInterventionPoint(
      InterventionPoint.AgentShutdown,
      { ...ambient, summary },
      mode,
    );
    await this.enforce(InterventionPoint.AgentShutdown, result, mode, resolver);
    return result;
  }

  /**
   * Framework-agnostic session seam: enforces `agent_startup` before `body`
   * runs and `agent_shutdown` after it completes cleanly. Shutdown is skipped
   * when `body` throws, so an in-session error is never masked by the shutdown
   * verdict. Set `session.summary` inside `body` to supply the shutdown target.
   */
  async withSession<T>(
    agent: JsonValue,
    body: (session: { summary: JsonValue }) => Promise<T> | T,
    options: {
      snapshot?: Record<string, JsonValue>;
      mode?: EnforcementMode;
      approvalResolver?: ApprovalResolver;
    } = {},
  ): Promise<T> {
    await this.agentStartup(agent, options);
    const session: { summary: JsonValue } = { summary: {} };
    const result = await body(session);
    await this.agentShutdown(session.summary, options);
    return result;
  }

}


function approvalResolverFailedResult(result: InterventionPointResult): InterventionPointResult {
  return {
    verdict: {
      decision: Decision.Deny,
      reason: "runtime_error:approval_resolver_failed",
      message: "Approval resolver failed closed.",
    },
    policyInput: result.policyInput,
    actionIdentity: result.actionIdentity,
  };
}

function requireApprovedIdentity(
  interventionPoint: InterventionPoint,
  result: InterventionPointResult,
  originalIdentity: string | undefined,
  approvedIdentity: string | undefined,
): void {
  const currentIdentity = result.policyInput === undefined ? undefined : actionIdentity(result.policyInput);
  if (
    originalIdentity !== undefined &&
    currentIdentity !== undefined &&
    approvedIdentity !== undefined &&
    originalIdentity === currentIdentity &&
    currentIdentity === approvedIdentity
  ) {
    return;
  }
  throw new AgentControlBlockedError(interventionPoint, {
    verdict: { decision: Decision.Deny, reason: "runtime_error:approval_action_mismatch" },
  });
}

export function actionIdentity(policyInput: JsonValue): string {
  return `sha256:${createHash("sha256").update(canonicalJson(policyInput), "utf8").digest("hex")}`;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  return `{${Object.keys(value)
    .sort(compareUnicodeScalarKeys)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, JsonValue>)[key])}`)
    .join(",")}}`;
}

function compareUnicodeScalarKeys(left: string, right: string): number {
  const leftScalars = Array.from(left);
  const rightScalars = Array.from(right);
  const length = Math.min(leftScalars.length, rightScalars.length);
  for (let index = 0; index < length; index += 1) {
    const leftCodePoint = leftScalars[index].codePointAt(0) ?? 0;
    const rightCodePoint = rightScalars[index].codePointAt(0) ?? 0;
    if (leftCodePoint !== rightCodePoint) return leftCodePoint - rightCodePoint;
  }
  return leftScalars.length - rightScalars.length;
}

function mapResult(raw: Record<string, JsonValue>): InterventionPointResult {
  // AGT D1.4: prefer the new bisected identity fields when the native
  // core exposes them, falling back to action_identity for older
  // binaries so a rollout stays tolerant of stale bindings.
  const legacyIdentity = raw.action_identity === null ? undefined : (raw.action_identity as string | undefined);
  const rawInputIdentity = raw.input_identity === null ? undefined : (raw.input_identity as string | undefined);
  const rawEnforcedIdentity = raw.enforced_identity === null ? undefined : (raw.enforced_identity as string | undefined);
  const inputIdentity = rawInputIdentity ?? legacyIdentity;
  const enforcedIdentity = rawEnforcedIdentity ?? legacyIdentity;
  const transformedPolicyTargetApplied = raw.transformed_policy_target_applied === true ||
    (raw.transformed_policy_target !== null && raw.transformed_policy_target !== undefined);
  return {
    verdict: mapVerdict(raw.verdict),
    transformedPolicyTarget: transformedPolicyTargetApplied ? raw.transformed_policy_target : undefined,
    transformedPolicyTargetApplied,
    policyInput: raw.policy_input === null ? undefined : raw.policy_input,
    inputIdentity,
    enforcedIdentity,
    // actionIdentity remains a back-compat alias for enforcedIdentity
    // so older callers reading the single-identity slot keep working.
    actionIdentity: enforcedIdentity,
  };
}

function mapVerdict(raw: JsonValue): Verdict {
  // The native binding emits snake_case keys from the Rust serde
  // derives; the public TS surface uses camelCase. We translate the
  // two known wire fields where the casing differs (result_labels and
  // evidence.verification_pointers) and pass the rest through. AGT D1
  // already forbids the legacy `effects` key, so this is the entire
  // translation surface.
  const wire = raw as Record<string, JsonValue> | null | undefined;
  if (wire === null || wire === undefined) {
    throw new Error("native runtime returned a missing verdict");
  }
  const decision = wire.decision as Decision;
  const reason = wire.reason === null ? undefined : (wire.reason as string | undefined);
  const message = wire.message === null ? undefined : (wire.message as string | undefined);
  const rawTransform = wire.transform as Record<string, JsonValue> | null | undefined;
  const transform: Transform | undefined = rawTransform
    ? { path: rawTransform.path as string, value: rawTransform.value }
    : undefined;
  const rawEvidence = wire.evidence as Record<string, JsonValue> | null | undefined;
  const evidence: Evidence | undefined = rawEvidence
    ? {
        artefact:
          rawEvidence.artefact === null || rawEvidence.artefact === undefined
            ? undefined
            : (rawEvidence.artefact as string),
        // AGT D2: snake_case verification_pointers on the wire → camelCase
        // verificationPointers in the public TS type. Preserving the
        // original key losses the documented surface and breaks every
        // consumer that follows the Evidence interface.
        verificationPointers:
          rawEvidence.verification_pointers === null ||
          rawEvidence.verification_pointers === undefined
            ? undefined
            : (rawEvidence.verification_pointers as Record<string, string>),
      }
    : undefined;
  const rawResultLabels = wire.result_labels;
  const resultLabels: string[] | undefined = Array.isArray(rawResultLabels)
    ? (rawResultLabels as string[])
    : undefined;
  return {
    decision,
    reason,
    message,
    transform,
    evidence,
    // Preserve the documented snake_case key on the Verdict surface;
    // it matches the wire and existing TS callers.
    result_labels: resultLabels,
  };
}

function normalizeToolCallId(toolCallId: string | undefined): string | undefined {
  if (toolCallId === undefined) {
    return undefined;
  }
  if (typeof toolCallId !== "string") {
    throw new TypeError("toolCallId must be a string.");
  }
  if (toolCallId.length === 0) {
    throw new Error("toolCallId must be a non-empty string when provided.");
  }
  return toolCallId;
}

function makeToolCall(toolName: string, args: JsonValue, toolCallId: string | undefined): Record<string, JsonValue> {
  const toolCall: Record<string, JsonValue> = { name: toolName, args };
  if (toolCallId !== undefined) {
    toolCall.id = toolCallId;
  }
  return toolCall;
}

export * from "./adapters";
export * from "./streaming";
export * from "./integrations/ghcp";
export * from "./integrations/opa-binary";
export * from "./integrations/bootstrap";
