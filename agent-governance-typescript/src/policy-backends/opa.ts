// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { BackendDecision, ExternalPolicyBackend } from '../types';

interface OPABackendConfig {
  endpoint: string;
  policyPath?: string;
  fetchImpl?: typeof fetch;
}

export class OPABackend implements ExternalPolicyBackend {
  readonly name = 'opa';
  private readonly endpoint: string;
  private readonly policyPath: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OPABackendConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.policyPath = config.policyPath ?? 'agentmesh/allow';
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async evaluateAction(action: string, context: Record<string, unknown>): Promise<BackendDecision> {
    const response = await this.fetchImpl(`${this.endpoint}/v1/data/${this.policyPath}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        input: {
          ...context,
          action,
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`OPA backend request failed with status ${response.status}`);
    }

    const body = await response.json() as {
      result?: boolean | { allow?: boolean; decision?: string };
    };
    if (typeof body.result === 'boolean') {
      return body.result ? 'allow' : 'deny';
    }

    if (body.result && typeof body.result === 'object') {
      if (typeof body.result.allow === 'boolean') {
        return body.result.allow ? 'allow' : 'deny';
      }

      if (body.result.decision === 'allow' || body.result.decision === 'deny' || body.result.decision === 'review') {
        return body.result.decision;
      }
    }

    throw new Error('OPA backend returned an unsupported result shape');
  }

  evaluatePolicy(agentDid: string, context: Record<string, unknown>): Promise<BackendDecision> {
    return this.evaluateAction('policy.evaluate', {
      ...context,
      agentDid,
    });
  }
}
