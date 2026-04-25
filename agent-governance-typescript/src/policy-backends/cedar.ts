// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { BackendDecision, ExternalPolicyBackend } from '../types';

interface CedarBackendConfig {
  endpoint: string;
  fetchImpl?: typeof fetch;
}

export class CedarBackend implements ExternalPolicyBackend {
  readonly name = 'cedar';
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: CedarBackendConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async evaluateAction(action: string, context: Record<string, unknown>): Promise<BackendDecision> {
    const response = await this.fetchImpl(this.endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        action,
        entities: context,
      }),
    });

    if (!response.ok) {
      throw new Error(`Cedar backend request failed with status ${response.status}`);
    }

    const body = await response.json() as {
      decision?: string;
      allow?: boolean;
    };
    if (body.decision === 'allow' || body.decision === 'deny' || body.decision === 'review') {
      return body.decision;
    }

    if (typeof body.allow === 'boolean') {
      return body.allow ? 'allow' : 'deny';
    }

    throw new Error('Cedar backend returned an unsupported result shape');
  }

  evaluatePolicy(agentDid: string, context: Record<string, unknown>): Promise<BackendDecision> {
    return this.evaluateAction('policy.evaluate', {
      ...context,
      principal: agentDid,
    });
  }
}
