// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  McpSession,
  McpSessionAuthConfig,
  McpSessionIssueResult,
  McpSessionTokenPayload,
  McpSessionVerificationResult,
} from './types';
import { InMemorySessionStore } from './stores';
import {
  AsyncKeyLock,
  createHmacHex,
  debugSecurityFailure,
  DefaultNonceGenerator,
  getSafeErrorMessage,
  McpSecurityError,
  safeEqualHex,
  stableStringify,
  SystemClock,
} from './utils';

const DEFAULT_TTL_MS = 15 * 60_000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 30_000;
const DEFAULT_MAX_CONCURRENT_SESSIONS = 3;

/**
 * Issues and validates MCP session tokens that are bound to agent identity.
 */
export class McpSessionAuthenticator {
  private readonly config: Required<
    Pick<McpSessionAuthConfig, 'ttlMs' | 'maxClockSkewMs' | 'maxConcurrentSessions'>
  > & McpSessionAuthConfig;
  private readonly agentLock = new AsyncKeyLock();

  constructor(config: McpSessionAuthConfig) {
    this.config = {
      ...config,
      ttlMs: config.ttlMs ?? DEFAULT_TTL_MS,
      maxClockSkewMs: config.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS,
      maxConcurrentSessions:
        config.maxConcurrentSessions ?? DEFAULT_MAX_CONCURRENT_SESSIONS,
      sessionStore: config.sessionStore ?? new InMemorySessionStore(),
      clock: config.clock ?? new SystemClock(),
      nonceGenerator: config.nonceGenerator ?? new DefaultNonceGenerator(),
    };
  }

  async issueToken(
    agentId: string,
      options: {
        sessionId?: string;
        metadata?: Record<string, string>;
      } = {},
  ): Promise<McpSessionIssueResult> {
    return this.agentLock.run(agentId, async () => {
      try {
        const now = this.config.clock!.now();
        await this.pruneExpired(agentId, now);

        const activeSessions = (await this.config.sessionStore!.listByAgent(agentId))
          .filter((session) => session.expiresAt.getTime() + this.config.maxClockSkewMs > now.getTime());
        if (activeSessions.length >= this.config.maxConcurrentSessions) {
          throw new McpSecurityError('Concurrent session limit exceeded');
        }

        const payload: McpSessionTokenPayload = {
          version: 'v1',
          sessionId: options.sessionId ?? this.config.nonceGenerator!.generate(),
          agentId,
          tokenId: this.config.nonceGenerator!.generate(),
          issuedAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + this.config.ttlMs).toISOString(),
          metadata: options.metadata,
        };

        const encodedPayload = Buffer.from(
          stableStringify(payload),
          'utf-8',
        ).toString('base64url');
        const signature = createHmacHex(this.config.secret, payload.version, encodedPayload);

        const session: McpSession = {
          id: payload.sessionId,
          agentId,
          tokenId: payload.tokenId,
          issuedAt: new Date(payload.issuedAt),
          expiresAt: new Date(payload.expiresAt),
          metadata: payload.metadata,
        };
        await this.config.sessionStore!.set(session);

        return {
          token: `${payload.version}.${encodedPayload}.${signature}`,
          payload,
        };
      } catch (error) {
        debugSecurityFailure(this.config.logger, 'sessionAuthenticator.issueToken', error);
        throw new McpSecurityError(getSafeErrorMessage(error, 'Internal error - access denied (fail-closed)'));
      }
    });
  }

  async verifyToken(
    token: string,
    expectedAgentId?: string,
  ): Promise<McpSessionVerificationResult> {
    try {
      const parts = token.split('.');
      if (parts.length !== 3 || parts[0] !== 'v1') {
        return { valid: false, reason: 'Invalid token format' };
      }

      const [, encodedPayload, signature] = parts;
      const expectedSignature = createHmacHex(this.config.secret, 'v1', encodedPayload);
      if (!safeEqualHex(signature, expectedSignature)) {
        return { valid: false, reason: 'Invalid token signature' };
      }

      const payload = JSON.parse(
        Buffer.from(encodedPayload, 'base64url').toString('utf-8'),
      ) as McpSessionTokenPayload;

      if (expectedAgentId && payload.agentId !== expectedAgentId) {
        return { valid: false, reason: 'Agent identity mismatch' };
      }

      const now = this.config.clock!.now();
      const expiresAt = new Date(payload.expiresAt);
      if (Number.isNaN(expiresAt.getTime())) {
        return { valid: false, reason: 'Invalid token payload' };
      }
      if (expiresAt.getTime() + this.config.maxClockSkewMs < now.getTime()) {
        return { valid: false, reason: 'Token expired' };
      }

      const session = await this.config.sessionStore!.get(payload.sessionId);
      if (!session) {
        return { valid: false, reason: 'Session not found' };
      }

      if (session.agentId !== payload.agentId || session.tokenId !== payload.tokenId) {
        return { valid: false, reason: 'Session token has been superseded' };
      }

      return {
        valid: true,
        payload,
      };
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'sessionAuthenticator.verifyToken', error);
      return {
        valid: false,
        reason: getSafeErrorMessage(error, 'Internal error - access denied (fail-closed)'),
      };
    }
  }

  async revokeSession(
    sessionIdOrAgentId: string,
    maybeSessionId?: string,
  ): Promise<void> {
    const sessionId = maybeSessionId ?? sessionIdOrAgentId;
    await this.agentLock.run(`session:${sessionId}`, async () => {
      await this.config.sessionStore!.delete(sessionId);
    });
  }

  private async pruneExpired(agentId: string, now: Date): Promise<void> {
    const sessions = await this.config.sessionStore!.listByAgent(agentId);
    for (const session of sessions) {
      if (session.expiresAt.getTime() + this.config.maxClockSkewMs < now.getTime()) {
        await this.config.sessionStore!.delete(session.id);
      }
    }
  }
}
