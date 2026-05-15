// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { BackendDecision, ExternalPolicyBackend } from '../types';

interface OPABackendConfig {
  endpoint: string;
  policyPath?: string;
  fetchImpl?: typeof fetch;
}

const BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
]);

function validateOpaUrl(endpoint: string): void {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error(`Invalid OPA endpoint URL: ${endpoint}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `Unsupported OPA URL scheme '${parsed.protocol}': only http and https are allowed`,
    );
  }
  if (BLOCKED_HOSTS.has(parsed.hostname)) {
    throw new Error(`OPA URL host '${parsed.hostname}' is blocked to prevent SSRF`);
  }
}

export class OPABackend implements ExternalPolicyBackend {
  readonly name = 'opa';
  private readonly endpoint: string;
  private readonly policyPath: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OPABackendConfig) {
    validateOpaUrl(config.endpoint);
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
