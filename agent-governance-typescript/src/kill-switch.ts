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
    this.callbackTimeoutMs = config.callbackTimeoutMs ?? DEFAULT_CALLBACK_TIMEOUT_MS;
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
