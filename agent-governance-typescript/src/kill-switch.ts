// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { KillSwitchConfig, KillSwitchResult } from './types';

export interface KillContext {
  action?: string;
  reason: string;
}

type KillHandler = (agentId: string, context: KillContext) => void | Promise<void>;

export class KillSwitch {
  private readonly enabled: boolean;
  private readonly defaultSubstituteAgentId?: string;
  private readonly handlers = new Map<string, KillHandler[]>();
  private readonly compensations = new Map<string, KillHandler[]>();
  private readonly substitutes = new Map<string, string>();
  private readonly history: KillSwitchResult[] = [];

  constructor(config: KillSwitchConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.defaultSubstituteAgentId = config.defaultSubstituteAgentId;
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

    for (const handler of handlers) {
      await handler(agentId, context);
    }

    for (const compensation of compensations) {
      await compensation(agentId, context);
    }

    const handoffAgentId = this.substitutes.get(agentId) ?? this.defaultSubstituteAgentId;
    const result: KillSwitchResult = {
      agentId,
      action: context.action,
      reason: context.reason,
      killedAt: new Date().toISOString(),
      callbacksExecuted: handlers.length,
      compensationsExecuted: compensations.length,
      handoffAgentId,
    };

    this.history.push(result);
    return result;
  }
}
