// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type {
  Decision,
  EnforcementMode,
  InterventionPoint,
  InterventionPointResult,
  JsonValue,
} from "./index";

export const DEFAULT_OTEL_METER_NAME = "agent_control_specification";

const DECISION_WIRE_STRINGS = ["allow", "deny", "warn", "escalate", "transform"] as const;
const MAX_REASON_CODE_BYTES = 96;
const REASON_CODE_EXTRA_CHARS = new Set(["_", "-", ".", ":", "/"]);

export const TelemetryEventType = Object.freeze({
  Decision: "decision",
  AnnotatorDispatch: "annotator_dispatch",
  PolicyEvaluation: "policy_evaluation",
  EvaluationTiming: "evaluation_timing",
  InterventionPointTransformed: "intervention_point.transformed",
  AnnotatorFailed: "annotator_failed",
  PolicyFailed: "policy_failed",
} as const);
export type TelemetryEventType = (typeof TelemetryEventType)[keyof typeof TelemetryEventType];

export interface TelemetryEventFields {
  eventType: TelemetryEventType;
  interventionPoint: InterventionPoint | string;
  decision?: Decision | null;
  reasonCode?: string | null;
  errorClass?: string | null;
  policyId?: string | null;
  annotators?: readonly string[];
  enforcementMode?: EnforcementMode | null;
  durationMs?: number | null;
  evidenceArtefact?: string | null;
  evidenceVerificationPointerKeys?: readonly string[];
  actionIdentity?: string | null;
  metadata?: Record<string, string>;
}

export interface TelemetryEventObject {
  eventType: TelemetryEventType;
  interventionPoint: InterventionPoint | string;
  decision: Decision | null;
  reasonCode: string | null;
  errorClass: string | null;
  policyId: string | null;
  annotators: string[];
  enforcementMode: EnforcementMode | null;
  durationMs: number | null;
  evidenceArtefact: string | null;
  evidenceVerificationPointerKeys: string[];
  actionIdentity: string | null;
  metadata: Record<string, string>;
}

export class TelemetryEvent {
  readonly eventType: TelemetryEventType;
  readonly interventionPoint: InterventionPoint | string;
  readonly decision: Decision | null;
  readonly reasonCode: string | null;
  readonly errorClass: string | null;
  readonly policyId: string | null;
  readonly annotators: readonly string[];
  readonly enforcementMode: EnforcementMode | null;
  readonly durationMs: number | null;
  readonly evidenceArtefact: string | null;
  readonly evidenceVerificationPointerKeys: readonly string[];
  readonly actionIdentity: string | null;
  readonly metadata: Readonly<Record<string, string>>;

  constructor(fields: TelemetryEventFields) {
    this.eventType = fields.eventType;
    this.interventionPoint = fields.interventionPoint;
    this.decision = fields.decision ?? null;
    this.reasonCode = fields.reasonCode ?? null;
    this.errorClass = fields.errorClass ?? null;
    this.policyId = fields.policyId ?? null;
    this.annotators = [...(fields.annotators ?? [])];
    this.enforcementMode = fields.enforcementMode ?? null;
    this.durationMs = fields.durationMs ?? null;
    this.evidenceArtefact = fields.evidenceArtefact ?? null;
    this.evidenceVerificationPointerKeys = [...(fields.evidenceVerificationPointerKeys ?? [])];
    this.actionIdentity = fields.actionIdentity ?? null;
    this.metadata = { ...(fields.metadata ?? {}) };
  }

  static fromResult(
    interventionPoint: InterventionPoint | string,
    mode: EnforcementMode | null,
    result: InterventionPointResult,
    durationMs: number | null,
    policyId: string | null = null,
    annotators?: readonly string[],
  ): TelemetryEvent {
    const verdict = result.verdict;
    const reason = verdict.reason;
    const evidence = verdict.evidence;
    const verificationPointers = evidence?.verificationPointers;
    const pointerKeys = isRecord(verificationPointers)
      ? Object.keys(verificationPointers).sort(compareUnicodeScalarKeys)
      : [];
    const artefact = evidence?.artefact;
    if (artefact !== undefined && artefact !== null && typeof artefact !== "string") {
      throw new TypeError("evidence artefact must be a string when provided");
    }
    return new TelemetryEvent({
      eventType: TelemetryEventType.Decision,
      interventionPoint,
      decision: verdict.decision,
      reasonCode: safeReasonCode(reason),
      errorClass: errorClassFor(reason),
      policyId,
      annotators: annotators ?? annotatorNames(result.policyInput),
      enforcementMode: mode,
      durationMs,
      evidenceArtefact: artefact ?? null,
      evidenceVerificationPointerKeys: pointerKeys,
      actionIdentity: result.actionIdentity ?? null,
      metadata: {},
    });
  }

  toObject(): TelemetryEventObject {
    return {
      eventType: this.eventType,
      interventionPoint: this.interventionPoint,
      decision: this.decision,
      reasonCode: this.reasonCode,
      errorClass: this.errorClass,
      policyId: this.policyId,
      annotators: [...this.annotators],
      enforcementMode: this.enforcementMode,
      durationMs: this.durationMs,
      evidenceArtefact: this.evidenceArtefact,
      evidenceVerificationPointerKeys: [...this.evidenceVerificationPointerKeys],
      actionIdentity: this.actionIdentity,
      metadata: { ...this.metadata },
    };
  }

  // Wire serialization with snake_case keys, matching the Rust, Python, and
  // .NET sinks so a mixed fleet writes one consistent audit.jsonl shape. The
  // camelCase toObject() stays the idiomatic in-memory view. JSON.stringify of
  // a TelemetryEvent uses this method.
  toJSON(): Record<string, JsonValue> {
    return {
      event_type: this.eventType,
      intervention_point: this.interventionPoint,
      decision: this.decision,
      reason_code: this.reasonCode,
      error_class: this.errorClass,
      policy_id: this.policyId,
      annotators: [...this.annotators],
      enforcement_mode: this.enforcementMode,
      duration_ms: this.durationMs,
      evidence_artefact: this.evidenceArtefact,
      evidence_verification_pointer_keys: [...this.evidenceVerificationPointerKeys],
      action_identity: this.actionIdentity,
      metadata: { ...this.metadata },
    };
  }
}

export function safeReasonCode(reason: string | null | undefined): string | null {
  if (reason === null || reason === undefined) {
    return null;
  }
  if (typeof reason !== "string") {
    throw new TypeError("reason must be a string when provided");
  }
  if (isIdentifierReasonCode(reason)) {
    return reason;
  }
  return "policy_reason";
}

export function errorClassFor(reason: string | null | undefined): string | null {
  if (reason !== null && reason !== undefined && typeof reason !== "string") {
    throw new TypeError("reason must be a string when provided");
  }
  return reason?.startsWith("runtime_error:") ? "runtime_error" : null;
}

function isIdentifierReasonCode(reason: string): boolean {
  if (reason.length === 0 || Buffer.byteLength(reason, "utf8") > MAX_REASON_CODE_BYTES) {
    return false;
  }
  for (const char of reason) {
    const code = char.charCodeAt(0);
    if (code >= 128) {
      return false;
    }
    const isAsciiAlphaNumeric =
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122);
    if (!isAsciiAlphaNumeric && !REASON_CODE_EXTRA_CHARS.has(char)) {
      return false;
    }
  }
  return true;
}

export interface TelemetrySink {
  emit(event: TelemetryEvent): void;
  forceFlush(): void;
  shutdown(): void;
}

export class InMemoryTelemetrySink implements TelemetrySink {
  readonly events: TelemetryEvent[] = [];

  emit(event: TelemetryEvent): void {
    this.events.push(event);
  }

  forceFlush(): void {}

  shutdown(): void {}

  clear(): void {
    this.events.length = 0;
  }
}

export class JsonStdoutTelemetrySink implements TelemetrySink {
  constructor(private readonly stream: NodeJS.WritableStream = process.stdout) {}

  emit(event: TelemetryEvent): void {
    this.stream.write(`${JSON.stringify(event.toJSON())}\n`);
  }

  forceFlush(): void {
    const maybeFlush = (this.stream as { flush?: () => void }).flush;
    if (typeof maybeFlush === "function") {
      maybeFlush.call(this.stream);
    }
  }

  shutdown(): void {
    this.forceFlush();
  }
}

export class MultiSink implements TelemetrySink {
  readonly sinks: readonly TelemetrySink[];

  constructor(sinks: readonly TelemetrySink[]) {
    this.sinks = [...sinks];
  }

  emit(event: TelemetryEvent): void {
    for (const sink of this.sinks) {
      try {
        sink.emit(event);
      } catch (error) {
        console.warn(`Telemetry sink ${sink.constructor?.name ?? "unknown"} raised in emit.`, error);
      }
    }
  }

  forceFlush(): void {
    for (const sink of this.sinks) {
      try {
        sink.forceFlush?.();
      } catch (error) {
        console.warn(`Telemetry sink ${sink.constructor?.name ?? "unknown"} raised in forceFlush.`, error);
      }
    }
  }

  shutdown(): void {
    for (const sink of this.sinks) {
      try {
        sink.shutdown?.();
      } catch (error) {
        console.warn(`Telemetry sink ${sink.constructor?.name ?? "unknown"} raised in shutdown.`, error);
      }
    }
  }
}

type OtelCounter = {
  add(value: number, attributes?: Record<string, string>): void;
};

type OtelHistogram = {
  record(value: number, attributes?: Record<string, string>): void;
};

type OtelMeter = {
  createCounter(name: string): OtelCounter;
  createHistogram(name: string): OtelHistogram;
};

type OtelMeterProvider = {
  getMeter(name: string): OtelMeter;
  forceFlush?: () => void;
  shutdown?: () => void;
};

export interface OtelMetricsTelemetrySinkOptions {
  meterProvider?: OtelMeterProvider;
}

export class OtelMetricsTelemetrySink implements TelemetrySink {
  private static importWarningEmitted = false;
  private readonly meterProvider: OtelMeterProvider | undefined;
  private readonly resolvedMeterProvider: OtelMeterProvider | undefined;
  private readonly decisionCounters = new Map<string, OtelCounter>();
  private durationHistogram: OtelHistogram | undefined;
  private isAvailable = false;
  readonly meterName: string;

  constructor(
    meterName: string = DEFAULT_OTEL_METER_NAME,
    options: OtelMetricsTelemetrySinkOptions = {},
  ) {
    this.meterName = meterName;
    this.meterProvider = options.meterProvider;
    let meter: OtelMeter;
    try {
      const otelApi = require("@opentelemetry/api") as {
        metrics: { getMeter(name: string): OtelMeter; getMeterProvider(): OtelMeterProvider };
      };
      this.resolvedMeterProvider = this.meterProvider ?? otelApi.metrics.getMeterProvider();
      meter = this.meterProvider?.getMeter(meterName) ?? otelApi.metrics.getMeter(meterName);
    } catch {
      if (!OtelMetricsTelemetrySink.importWarningEmitted) {
        OtelMetricsTelemetrySink.importWarningEmitted = true;
        console.warn(
          "@opentelemetry/api is not installed. OtelMetricsTelemetrySink is a no-op until the package is available.",
        );
      }
      return;
    }

    for (const decision of DECISION_WIRE_STRINGS) {
      this.decisionCounters.set(decision, meter.createCounter(`acs_intervention_${decision}_total`));
    }
    this.durationHistogram = meter.createHistogram("acs_intervention_duration_ms");
    this.isAvailable = true;
  }

  get available(): boolean {
    return this.isAvailable;
  }

  emit(event: TelemetryEvent): void {
    if (!this.isAvailable) {
      return;
    }
    // Record one increment and one duration sample per evaluation. Only the
    // base decision event records metrics, matching the Rust OTel sink, so a
    // non-decision event fed in directly cannot double-count.
    if (event.eventType !== TelemetryEventType.Decision) {
      return;
    }
    const attributes = otelAttributes(event);
    if (event.decision !== null) {
      this.decisionCounters.get(event.decision)?.add(1, attributes);
    }
    if (event.durationMs !== null) {
      this.durationHistogram?.record(event.durationMs, attributes);
    }
  }

  forceFlush(): void {
    if (!this.isAvailable) {
      return;
    }
    this.resolvedMeterProvider?.forceFlush?.();
  }

  shutdown(): void {
    if (!this.isAvailable) {
      return;
    }
    this.resolvedMeterProvider?.shutdown?.();
  }
}

export function coerceTelemetrySink(
  sink: TelemetrySink | readonly TelemetrySink[] | null | undefined,
): TelemetrySink | undefined {
  if (sink === null || sink === undefined) {
    return undefined;
  }
  if (Array.isArray(sink)) {
    return new MultiSink(sink.map((child) => requireTelemetrySink(child)));
  }
  return requireTelemetrySink(sink);
}

export function labelsFromClient(runtimeClient: unknown): {
  policyIds: Record<string, string>;
  annotators: Record<string, string[]>;
} {
  // Read the runtime client's policyLabels map, which the native client sources
  // from the merged manifest, so labels are populated on every native-backed
  // constructor including fromUrl and fromManifestChain and for extends-inherited
  // bindings. A client without policyLabels yields empty indexes, so policyId is
  // null and annotators fall back to executed annotation keys on the result.
  // Never throws, since telemetry labels are best effort.
  const policyIds: Record<string, string> = {};
  const annotators: Record<string, string[]> = {};
  const getter = (runtimeClient as { policyLabels?: unknown } | null)?.policyLabels;
  if (typeof getter !== "function") {
    return { policyIds, annotators };
  }
  let labels: unknown;
  try {
    labels = (getter as () => unknown).call(runtimeClient);
  } catch {
    return { policyIds, annotators };
  }
  if (!isRecord(labels)) {
    return { policyIds, annotators };
  }
  for (const [point, entry] of Object.entries(labels)) {
    if (!isRecord(entry)) {
      continue;
    }
    const pointKey = normalizeInterventionPointKey(point);
    if (typeof entry.policy_id === "string") {
      policyIds[pointKey] = entry.policy_id;
    }
    const names = entry.annotators;
    if (Array.isArray(names) && names.length > 0) {
      annotators[pointKey] = names.map((name) => String(name)).sort(compareUnicodeScalarKeys);
    }
  }
  return { policyIds, annotators };
}

function requireTelemetrySink(sink: unknown): TelemetrySink {
  if (!isObject(sink) || typeof (sink as { emit?: unknown }).emit !== "function") {
    throw new TypeError(
      `telemetrySink must be a TelemetrySink with an emit() method or an array of sinks, got ${typeName(sink)}`,
    );
  }
  return sink as TelemetrySink;
}

function otelAttributes(event: TelemetryEvent): Record<string, string> {
  const attributes: Record<string, string> = {
    event_type: event.eventType,
    intervention_point: String(event.interventionPoint),
  };
  if (event.enforcementMode !== null) attributes.enforcement_mode = event.enforcementMode;
  if (event.decision !== null) attributes.decision = event.decision;
  if (event.reasonCode !== null) attributes.reason_code = event.reasonCode;
  if (event.errorClass !== null) attributes.error_class = event.errorClass;
  if (event.policyId !== null) attributes.policy_id = event.policyId;
  if (event.annotators.length > 0) attributes.annotators = event.annotators.join(",");
  if (event.evidenceArtefact !== null) attributes.evidence_artefact = event.evidenceArtefact;
  if (event.evidenceVerificationPointerKeys.length > 0) {
    attributes.evidence_verification_pointer_keys = event.evidenceVerificationPointerKeys.join(",");
  }
  return attributes;
}

function annotatorNames(policyInput: JsonValue | undefined): string[] {
  if (!isRecord(policyInput) || !isRecord(policyInput.annotations)) {
    return [];
  }
  return Object.keys(policyInput.annotations).sort(compareUnicodeScalarKeys);
}

const INTERVENTION_POINT_NAME_TO_WIRE: Record<string, string> = {
  AgentStartup: "agent_startup",
  Input: "input",
  PreModelCall: "pre_model_call",
  PostModelCall: "post_model_call",
  PreToolCall: "pre_tool_call",
  PostToolCall: "post_tool_call",
  Output: "output",
  AgentShutdown: "agent_shutdown",
};

function normalizeInterventionPointKey(point: string): string {
  return INTERVENTION_POINT_NAME_TO_WIRE[point] ?? point;
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

function isRecord(value: unknown): value is Record<string, JsonValue> {
  return isObject(value) && !Array.isArray(value);
}

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}

function typeName(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  return value.constructor?.name ?? typeof value;
}
