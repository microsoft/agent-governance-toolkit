import type {
  AgentControl,
  Decision,
  EnforcementMode,
  InterventionPoint,
  InterventionPointResult,
  JsonValue,
} from "./index";

const ENFORCE_MODE = "enforce";
const EVALUATE_ONLY_MODE = "evaluate_only";
// AGT D1: the transform decision is the only verdict that mutates the
// policy target. The pre-AGT set (allow|warn|escalate) was wrong because
// escalate must never mutate, and allow/warn cannot carry a transform
// either. Replace EFFECT_APPLYING_DECISIONS with a TRANSFORM_DECISIONS
// set so callers gate strictly on the new mutation path.
const TRANSFORM_DECISIONS = new Set<string>(["transform"]);

export interface AdapterOptions {
  snapshot?: Record<string, JsonValue>;
  mode?: EnforcementMode;
  toolCallId?: string;
  toolName?: string;
  methodName?: string | symbol;
  methods?: Array<string | symbol>;
  modelRequest?: JsonValue;
  model_request?: JsonValue;
  approvalResolver?: import("./index").ApprovalResolver;
}

export type RunnableControl = Pick<
  AgentControl,
  "evaluateInterventionPoint" | "run" | "runTool" | "protectTool" | "enforce" | "withSession"
>;

export class AgentControlInterruptionError extends Error {
  public readonly interventionPoint: InterventionPoint;
  public readonly result: InterventionPointResult;

  constructor(message: string, interventionPoint: InterventionPoint, result: InterventionPointResult) {
    super(message);
    this.name = "AgentControlInterruptionError";
    this.interventionPoint = interventionPoint;
    this.result = result;
  }
}

export class AgentControlBlockedError extends AgentControlInterruptionError {
  constructor(interventionPoint: InterventionPoint, result: InterventionPointResult) {
    const reason = result.verdict.reason ? ` (${result.verdict.reason})` : "";
    super(`Agent Control Specification blocked ${interventionPoint}${reason}.`, interventionPoint, result);
    this.name = "AgentControlBlockedError";
  }
}

export class AgentControlSuspendedError extends AgentControlInterruptionError {
  public readonly handle: JsonValue | undefined;

  constructor(interventionPoint: InterventionPoint, result: InterventionPointResult, handle?: JsonValue) {
    const reason = result.verdict.reason ? ` (${result.verdict.reason})` : "";
    super(
      `Agent Control Specification suspended ${interventionPoint} pending approval${reason}.`,
      interventionPoint,
      result,
    );
    this.name = "AgentControlSuspendedError";
    this.handle = handle;
  }
}

/**
 * True only for `Decision.Transform`, the sole mutating verdict per
 * AGT D1.1. `Decision.appliesEffects` is retained as a deprecated
 * alias and now delegates to this predicate; consumers SHOULD migrate
 * to `appliesTransform`.
 */
export function appliesTransform(decision: Decision): boolean {
  return TRANSFORM_DECISIONS.has(decision);
}

/**
 * @deprecated Use {@link appliesTransform}. AGT D1 removed effects[],
 * so only `Decision.Transform` mutates the policy target. The pre-AGT
 * surface returned true for allow, warn, and escalate; this alias now
 * returns the same answer as `appliesTransform` so callers that
 * already relied on it still gate correctly under AGT.
 */
export function appliesEffects(decision: Decision): boolean {
  return appliesTransform(decision);
}

export function transformedOr<T extends JsonValue>(
  result: InterventionPointResult,
  fallback: T,
  mode: EnforcementMode = ENFORCE_MODE as EnforcementMode,
): JsonValue {
  // AGT D1: the SDK MUST return the engine's transformedPolicyTarget
  // only when the verdict was Decision.Transform in enforce mode. Every
  // other verdict (allow, warn, deny, escalate) keeps the fallback.
  if (mode !== ENFORCE_MODE) return fallback;
  if (!appliesTransform(result.verdict.decision)) return fallback;
  if (result.transformedPolicyTargetApplied) {
    return spliceNestedPolicyTarget(result, fallback, result.transformedPolicyTarget ?? null);
  }
  return result.transformedPolicyTarget === undefined
    ? fallback
    : spliceNestedPolicyTarget(result, fallback, result.transformedPolicyTarget);
}

function spliceNestedPolicyTarget<T extends JsonValue>(
  result: InterventionPointResult,
  fallback: T,
  transformed: JsonValue,
): JsonValue {
  const relativePath = relativeSnapshotPath(policyTargetPath(result));
  if (relativePath === undefined || relativePath.length === 0) return transformed;
  const cloned = cloneJsonValue(fallback);
  return setRelativeJsonPath(cloned, relativePath, transformed) ? cloned : transformed;
}

function policyTargetPath(result: InterventionPointResult): string | undefined {
  if (!isObject(result.policyInput)) return undefined;
  const policyTarget = result.policyInput.policy_target ?? result.policyInput.policyTarget;
  if (!isObject(policyTarget)) return undefined;
  return typeof policyTarget.path === "string" ? policyTarget.path : undefined;
}

function relativeSnapshotPath(path: string | undefined): string | undefined {
  if (path === undefined) return undefined;
  const rest = path.startsWith("$.")
    ? path.slice(2)
    : path.startsWith("$snap.")
      ? path.slice(6)
      : undefined;
  if (rest === undefined) return undefined;
  let firstSegmentEnd = rest.length;
  for (const delimiter of [".", "["]) {
    const index = rest.indexOf(delimiter);
    if (index >= 0) firstSegmentEnd = Math.min(firstSegmentEnd, index);
  }
  return firstSegmentEnd === rest.length ? "" : rest.slice(firstSegmentEnd);
}

function cloneJsonValue<T extends JsonValue>(value: T): T {
  return value === undefined ? value : JSON.parse(JSON.stringify(value)) as T;
}

function setRelativeJsonPath(root: JsonValue, path: string, value: JsonValue): boolean {
  const segments = relativePathSegments(path);
  if (segments.length === 0) return false;
  let current: JsonValue = root;
  for (const segment of segments.slice(0, -1)) {
    if (typeof segment === "string") {
      if (!isObject(current) || !(segment in current)) return false;
      current = current[segment];
    } else {
      if (!Array.isArray(current) || segment < 0 || segment >= current.length) return false;
      current = current[segment];
    }
  }
  const last = segments[segments.length - 1];
  if (typeof last === "string") {
    if (!isObject(current) || !(last in current)) return false;
    current[last] = value;
    return true;
  }
  if (!Array.isArray(current) || last < 0 || last >= current.length) return false;
  current[last] = value;
  return true;
}

function relativePathSegments(path: string): Array<string | number> {
  const segments: Array<string | number> = [];
  let index = 0;
  while (index < path.length) {
    if (path[index] === ".") {
      index += 1;
      const start = index;
      while (index < path.length && path[index] !== "." && path[index] !== "[") index += 1;
      if (start === index) return [];
      segments.push(path.slice(start, index));
    } else if (path[index] === "[") {
      const end = path.indexOf("]", index);
      if (end < 0) return [];
      const parsed = Number.parseInt(path.slice(index + 1, end), 10);
      if (!Number.isInteger(parsed)) return [];
      segments.push(parsed);
      index = end + 1;
    } else {
      return [];
    }
  }
  return segments;
}

export function normalizeMode(mode: EnforcementMode = ENFORCE_MODE as EnforcementMode): EnforcementMode {
  if (mode !== ENFORCE_MODE && mode !== EVALUATE_ONLY_MODE) {
    throw new TypeError(`Unknown Agent Control Specification enforcement mode: ${String(mode)}`);
  }
  return mode;
}

export function mergeOptions(
  defaultOptions: AdapterOptions = {},
  callOptions: AdapterOptions = {},
): AdapterOptions {
  const base = isObject(defaultOptions) ? defaultOptions : {};
  const call = isObject(callOptions) ? callOptions : {};
  return {
    ...base,
    ...call,
    snapshot: {
      ...(base.snapshot ?? {}),
      ...(call.snapshot ?? {}),
    },
  };
}

export function extractAdapterOptions(value: unknown): AdapterOptions {
  if (!isObject(value)) return {};
  const configurable = isObject(value.configurable) ? value.configurable : {};
  const options = value.agentControl ?? value.agent_control ?? configurable.agentControl ?? {};
  return isObject(options) ? (options as AdapterOptions) : {};
}

export function assertAgentControl(control: unknown): asserts control is RunnableControl {
  if (!hasAgentControlSurface(control)) {
    throw new TypeError("control must expose evaluateInterventionPoint(), run(), runTool(), protectTool(), and withSession()");
  }
}

export function hasAgentControlSurface(control: unknown): control is RunnableControl {
  return (
    !isObject(control) ||
    typeof control.evaluateInterventionPoint !== "function" ||
    typeof control.run !== "function" ||
    typeof control.runTool !== "function" ||
    typeof control.protectTool !== "function" ||
    typeof control.withSession !== "function"
  ) ? false : true;
}

export function assertObject(value: unknown, label: string): asserts value is Record<PropertyKey, unknown> {
  if (!isObject(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

export function adapterMethods(options: AdapterOptions, fallback: Array<string | symbol>): Array<string | symbol> {
  if (options.methodName !== undefined) return [options.methodName];
  return options.methods ?? fallback;
}

export function ensureHasMethod(
  target: Record<PropertyKey, unknown>,
  methods: Array<string | symbol>,
  label: string,
): void {
  if (!methods.some((method) => typeof target[method] === "function")) {
    throw new TypeError(`${label} must expose one of: ${methods.map(String).join(", ")}`);
  }
}

export function policyJsonValue(value: unknown, seen: WeakSet<object> = new WeakSet()): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "undefined" || typeof value === "function" || typeof value === "symbol") {
    return null;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    const out = value.map((item) => policyJsonValue(item, seen));
    seen.delete(value);
    return out;
  }
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object") {
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    const toJson = (value as { toJSON?: unknown }).toJSON;
    if (typeof toJson === "function") {
      try {
        const out = policyJsonValue(toJson.call(value), seen);
        seen.delete(value);
        return out;
      } catch {
        // Some framework result objects expose toJSON methods that validate for
        // persistence, not policy snapshots. Fall back to enumerable state.
      }
    }
    const out: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (typeof item !== "undefined" && typeof item !== "function" && typeof item !== "symbol") {
        out[key] = policyJsonValue(item, seen);
      }
    }
    seen.delete(value);
    return out;
  }
  return null;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
