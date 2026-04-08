// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  MCPSessionAuthConfig,
  MCPSessionIssueResult,
  MCPSessionRecord,
  MCPSessionStore,
  MCPSessionTokenPayload,
  MCPSessionVerificationResult,
} from './types';
import {
  DEFAULT_MCP_CLOCK,
  createHmacHex,
  normalizeSecret,
  randomNonce,
  stableStringify,
  toTimestamp,
  timingSafeEqualHex,
} from './mcp-utils';

const TOKEN_VERSION = 'v1';
const DEFAULT_TTL_MS = 15 * 60_000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 30_000;
const DEFAULT_MAX_CONCURRENT_SESSIONS = 3;

export class InMemoryMCPSessionStore implements MCPSessionStore {
  private readonly sessions = new Map<string, Map<string, MCPSessionRecord>>();

  listSessions(agentId: string): MCPSessionRecord[] {
    return [...(this.sessions.get(agentId)?.values() ?? [])];
  }

  getSession(
    agentId: string,
    sessionId: string,
  ): MCPSessionRecord | undefined {
    return this.sessions.get(agentId)?.get(sessionId);
  }

  upsertSession(record: MCPSessionRecord): void {
    let bucket = this.sessions.get(record.agentId);
    if (!bucket) {
      bucket = new Map();
      this.sessions.set(record.agentId, bucket);
    }
    bucket.set(record.sessionId, record);
  }

  removeSession(agentId: string, sessionId: string): void {
    this.sessions.get(agentId)?.delete(sessionId);
  }
}

export class MCPSessionAuthenticator {
  private readonly config: Required<
    Pick<MCPSessionAuthConfig, 'ttlMs' | 'maxConcurrentSessions' | 'maxClockSkewMs'>
  > & MCPSessionAuthConfig;
  private readonly sessionStore: MCPSessionStore;
  private readonly sessionOwners = new Map<string, string>();

  constructor(config: MCPSessionAuthConfig) {
    const key = normalizeSecret(config.secret);
    if (key.length < 32) {
      throw new Error('HMAC secret must be at least 32 bytes');
    }
    this.config = {
      ...config,
      ttlMs: config.ttlMs ?? DEFAULT_TTL_MS,
      maxConcurrentSessions:
        config.maxConcurrentSessions ?? DEFAULT_MAX_CONCURRENT_SESSIONS,
      maxClockSkewMs: config.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS,
    };
    this.sessionStore = config.sessionStore ?? new InMemoryMCPSessionStore();
  }

  async issueToken(
    agentId: string,
    options: {
      sessionId?: string;
      metadata?: Record<string, string>;
    } = {},
  ): Promise<MCPSessionIssueResult> {
    const now = this.now();
    await this.pruneExpired(agentId, now);

    const activeSessions = (await this.sessionStore.listSessions(agentId)).filter(
      (session) => session.expiresAt + this.config.maxClockSkewMs > now,
    );
    if (activeSessions.length >= this.config.maxConcurrentSessions) {
      throw new Error(
        `Concurrent session limit exceeded for '${agentId}' (${this.config.maxConcurrentSessions})`,
      );
    }

    const payload: MCPSessionTokenPayload = {
      tokenVersion: TOKEN_VERSION,
      agentId,
      sessionId: options.sessionId ?? randomNonce(12),
      issuedAt: now,
      expiresAt: now + this.config.ttlMs,
      nonce: randomNonce(),
      metadata: options.metadata,
    };

    const encodedPayload = Buffer.from(
      stableStringify(payload),
      'utf-8',
    ).toString('base64url');
    const signature = createHmacHex(
      this.config.secret,
      TOKEN_VERSION,
      encodedPayload,
    );

    await this.sessionStore.upsertSession({
      agentId,
      sessionId: payload.sessionId,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      tokenId: payload.nonce,
      metadata: payload.metadata,
    });
    this.sessionOwners.set(payload.sessionId, agentId);

    return {
      token: `${TOKEN_VERSION}.${encodedPayload}.${signature}`,
      payload,
    };
  }

  async verifyToken(
    token: string,
    expectedAgentId?: string,
  ): Promise<MCPSessionVerificationResult> {
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) {
      return { valid: false, reason: 'Invalid token format' };
    }

    const [, encodedPayload, signature] = parts;
    const expectedSignature = createHmacHex(
      this.config.secret,
      TOKEN_VERSION,
      encodedPayload,
    );
    if (!timingSafeEqualHex(signature, expectedSignature)) {
      return { valid: false, reason: 'Invalid token signature' };
    }

    let payload: MCPSessionTokenPayload;
    try {
      payload = JSON.parse(
        Buffer.from(encodedPayload, 'base64url').toString('utf-8'),
      ) as MCPSessionTokenPayload;
    } catch {
      return { valid: false, reason: 'Invalid token payload' };
    }

    if (expectedAgentId && payload.agentId !== expectedAgentId) {
      return { valid: false, reason: 'Agent identity mismatch' };
    }

    const now = this.now();
    if (payload.expiresAt + this.config.maxClockSkewMs < now) {
      return { valid: false, reason: 'Token expired' };
    }

    const session = await this.sessionStore.getSession(
      payload.agentId,
      payload.sessionId,
    );
    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    if (session.tokenId !== payload.nonce) {
      return { valid: false, reason: 'Session token has been superseded' };
    }

    return {
      valid: true,
      payload,
    };
  }

  async revokeSession(agentIdOrSessionId: string, maybeSessionId?: string): Promise<void> {
    const sessionId = maybeSessionId ?? agentIdOrSessionId;
    const agentId = maybeSessionId
      ? agentIdOrSessionId
      : this.sessionOwners.get(sessionId);
    if (!agentId) {
      return;
    }
    this.sessionOwners.delete(sessionId);
    await this.sessionStore.removeSession(agentId, sessionId);
  }

  private async pruneExpired(agentId: string, now: number): Promise<void> {
    const sessions = await this.sessionStore.listSessions(agentId);
    for (const session of sessions) {
      if (session.expiresAt + this.config.maxClockSkewMs < now) {
        this.sessionOwners.delete(session.sessionId);
        await this.sessionStore.removeSession(agentId, session.sessionId);
      }
    }
  }

  private now(): number {
    return toTimestamp((this.config.clock ?? DEFAULT_MCP_CLOCK).now());
  }
}
