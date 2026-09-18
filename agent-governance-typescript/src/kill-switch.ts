// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { KillSwitchConfig, KillSwitchResult } from './types';

export interface KillContext {
  action?: string;
  reason: string;
}

type KillHandler = (agentId: string, context: KillContext) => void | Promise<void>;

/**
 * Wall time we wait for a single kill callback before declaring it hung. A slow
 * or hung callback must not freeze the kill flow, because the whole point of a
 * kill switch is responsiveness. Mirrors `DEFAULT_CALLBACK_TIMEOUT_SECONDS` in
 * the Python kill switch.
 */
export const DEFAULT_CALLBACK_TIMEOUT_MS = 5000;

/**
 * Longest delay `setTimeout` can represent. The delay is stored in a signed
 * 32-bit integer, and anything larger silently degrades to ~1ms, so larger
 * budgets are clamped to this instead of being passed through.
 */
export const MAX_CALLBACK_TIMEOUT_MS = 2_147_483_647;

/**
 * Turn a configured callback budget into a delay `setTimeout` actually honours.
 *
 * `0`, negatives, `NaN` and anything past the timer ceiling all arrive at
 * `setTimeout` as a ~1ms delay. That would abandon every async termination and
 * compensation callback after a single tick while `kill()` still resolved
 * normally with `callbacksExecuted: 0` — a fail-open on a containment control,
 * reachable from plausible operator config, since both `0` and `Infinity` are
 * common "no timeout" conventions. So non-finite and non-positive values fall
 * back to the default (matching how the sandbox timeout is guarded), and a
 * finite budget beyond the ceiling is clamped to it (~24.8 days), which is the
 * longest wait a timer can express.
 */
function resolveCallbackTimeoutMs(configured: number | undefined): number {
  if (configured === undefined) {
    return DEFAULT_CALLBACK_TIMEOUT_MS;
  }

  if (!Number.isFinite(configured) || configured <= 0) {
    console.warn(
      `KillSwitch: callbackTimeoutMs must be a positive, finite number; got ` +
        `${String(configured)}, falling back to ${DEFAULT_CALLBACK_TIMEOUT_MS}ms`,
    );
    return DEFAULT_CALLBACK_TIMEOUT_MS;
  }

  if (configured > MAX_CALLBACK_TIMEOUT_MS) {
    console.warn(
      `KillSwitch: callbackTimeoutMs ${configured} exceeds the ` +
        `${MAX_CALLBACK_TIMEOUT_MS}ms timer ceiling; clamping to it`,
    );
    return MAX_CALLBACK_TIMEOUT_MS;
  }

  return configured;
}

export class KillSwitch {
  private readonly enabled: boolean;
  private readonly defaultSubstituteAgentId?: string;
  private readonly callbackTimeoutMs: number;
  private readonly handlers = new Map<string, KillHandler[]>();
  private readonly compensations = new Map<string, KillHandler[]>();
  private readonly substitutes = new Map<string, string>();
  private readonly history: KillSwitchResult[] = [];

  constructor(config: KillSwitchConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.defaultSubstituteAgentId = config.defaultSubstituteAgentId;
    this.callbackTimeoutMs = resolveCallbackTimeoutMs(config.callbackTimeoutMs);
  }

  registerHandler(agentId: string, handler: KillHandler): void {
    const existing = this.handlers.get(agentId) ?? [];
    existing.push(handler);
    this.handlers.set(agentId, existing);
  }

  registerCompensation(agentId: string, handler: KillHandler): void {
    const existing = this.compensations.get(agentId) ?? [];
    existing.push(handler);
    this.compensations.set(agentId, existing);
  }

  registerSubstitute(agentId: string, substituteAgentId: string): void {
    this.substitutes.set(agentId, substituteAgentId);
  }

  getHistory(): KillSwitchResult[] {
    return [...this.history];
  }

  async kill(agentId: string, context: KillContext): Promise<KillSwitchResult> {
    if (!this.enabled) {
      throw new Error('Kill switch is disabled');
    }

    const handlers = this.handlers.get(agentId) ?? [];
    const compensations = this.compensations.get(agentId) ?? [];

    let callbacksExecuted = 0;
    for (const handler of handlers) {
      if (await this.runBounded(handler, agentId, context, 'termination handler')) {
        callbacksExecuted += 1;
      }
    }

    let compensationsExecuted = 0;
    for (const compensation of compensations) {
      if (await this.runBounded(compensation, agentId, context, 'compensation')) {
        compensationsExecuted += 1;
      }
    }

    const handoffAgentId = this.substitutes.get(agentId) ?? this.defaultSubstituteAgentId;
    const result: KillSwitchResult = {
      agentId,
      action: context.action,
      reason: context.reason,
      killedAt: new Date().toISOString(),
      // Every registered handler must finish. A notifier completing while the
      // handler that actually stops the process hung or threw is not containment.
      terminated: handlers.length > 0 && callbacksExecuted === handlers.length,
      callbacksExecuted,
      compensationsExecuted,
      handoffAgentId,
    };

    this.history.push(result);
    return result;
  }

  /**
   * Run a single callback under `callbackTimeoutMs`, returning whether it
   * completed cleanly. A callback that rejects is reported as not executed
   * rather than propagating, so one failing callback cannot abort the kill and
   * leave it unrecorded.
   *
   * A hung callback cannot be cancelled in JavaScript, so it is abandoned and
   * left pending. The Python port abandons a daemon thread for the same reason.
   */
  private async runBounded(
    handler: KillHandler,
    agentId: string,
    context: KillContext,
    label: string,
  ): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | undefined;

    // The async wrapper turns a synchronous throw into a rejection, and the
    // catch keeps that rejection from going unhandled when the timeout wins.
    const completion = (async () => {
      await handler(agentId, context);
      return true;
    })().catch((error: unknown) => {
      console.warn(`KillSwitch: ${label} for '${agentId}' failed: ${String(error)}`);
      return false;
    });

    const timeout = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => {
        console.warn(
          `KillSwitch: ${label} for '${agentId}' exceeded ${this.callbackTimeoutMs}ms; abandoning it`,
        );
        resolve(false);
      }, this.callbackTimeoutMs);
    });

    try {
      return await Promise.race([completion, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }
}
