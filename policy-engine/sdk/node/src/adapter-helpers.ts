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
const EFFECT_APPLYING_DECISIONS = new Set(["allow", "warn", "escalate"]);

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

export function appliesEffects(decision: Decision): boolean {
  return EFFECT_APPLYING_DECISIONS.has(decision);
}

export function transformedOr<T extends JsonValue>(
  result: InterventionPointResult,
  fallback: T,
  mode: EnforcementMode = ENFORCE_MODE as EnforcementMode,
): JsonValue {
  if (mode !== ENFORCE_MODE) return fallback;
  if (!appliesEffects(result.verdict.decision)) return fallback;
  return result.transformedPolicyTarget === undefined ? fallback : result.transformedPolicyTarget;
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
  if (
    !isObject(control) ||
    typeof control.evaluateInterventionPoint !== "function" ||
    typeof control.run !== "function" ||
    typeof control.runTool !== "function" ||
    typeof control.protectTool !== "function" ||
    typeof control.withSession !== "function"
  ) {
    throw new TypeError("control must expose evaluateInterventionPoint(), run(), runTool(), protectTool(), and withSession()");
  }
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
