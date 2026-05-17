// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { BackendDecision, ExternalPolicyBackend } from '../types';

/** Hostnames and IP prefixes that must never be used as Cedar endpoints. */
const SSRF_BLOCKLIST = [
  '169.254.169.254',    // AWS/Azure IMDS
  '169.254.170.2',      // ECS task metadata
  '168.63.129.16',      // Azure Wire Server
  'metadata.google.internal',
  'metadata.google',
  '100.100.100.200',    // Alibaba Cloud IMDS
  'fd00::',             // IPv6 unique-local prefix
  '::1',                // IPv6 loopback
];

const SSRF_PRIVATE_RANGES = [
  /^127\./,             // IPv4 loopback
  /^10\./,              // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,        // RFC 1918
  /^0\./,               // "this" network
];

function isBlockedEndpoint(endpoint: string): boolean {
  let hostname: string;
  try {
    const url = new URL(endpoint);
    hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return true;
    }
  } catch {
    return true;
  }

  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || SSRF_BLOCKLIST.some(b => lower === b || lower.endsWith('.' + b))) {
    return true;
  }
  if (SSRF_PRIVATE_RANGES.some(re => re.test(hostname))) {
    return true;
  }
  return false;
}

interface CedarBackendConfig {
  endpoint: string;
  fetchImpl?: typeof fetch;
}

export class CedarBackend implements ExternalPolicyBackend {
  readonly name = 'cedar';
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: CedarBackendConfig) {
    const cleaned = config.endpoint.replace(/\/$/, '');
    if (isBlockedEndpoint(cleaned)) {
      throw new Error('Cedar endpoint blocked: URL points to a reserved or private address');
    }
    this.endpoint = cleaned;
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
