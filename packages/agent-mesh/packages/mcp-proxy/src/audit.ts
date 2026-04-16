// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Logger - CloudEvents format
 * 
 * Logs all tool invocations and policy decisions in CloudEvents v1.0 format.
 */

import { createWriteStream, WriteStream } from 'fs';
import { createHash, randomUUID } from 'crypto';

export interface AuditLoggerOptions {
  path?: string;
  format?: 'json' | 'cloudevents';
}

export interface AuditEvent {
  type: string;
  tool: string;
  arguments?: Record<string, any>;
  decision: 'allow' | 'deny';
  reason?: string;
  rule?: string;
  mitigates?: string[];
  latency_ms?: number;
}

export class AuditLogger {
  private options: AuditLoggerOptions;
  private stream: WriteStream | null = null;
  private previousHash: string = '0'.repeat(64);
  private source: string;

  constructor(options: AuditLoggerOptions = {}) {
    this.options = {
      format: 'cloudevents',
      ...options,
    };
    this.source = `urn:agentmesh-mcp-proxy:${process.pid}`;

    if (options.path) {
      this.stream = createWriteStream(options.path, { flags: 'a' });
    }
  }

  log(event: AuditEvent): void {
    const cloudEvent = this.formatCloudEvent(event);
    const line = JSON.stringify(cloudEvent);

    // Write to file
    if (this.stream) {
      this.stream.write(line + '\n');
    }

    // Also log to stderr in verbose mode
    if (process.env.AGENTMESH_VERBOSE) {
      console.error(`[audit] ${event.decision}: ${event.tool}`, event.reason || '');
    }
  }

  private formatCloudEvent(event: AuditEvent): object {
    const id = randomUUID();
    const time = new Date().toISOString();

    // Compute hash chain hash for tamper detection
    const dataJson = JSON.stringify(event);
    const entryHash = this.computeHash(`${this.previousHash}:${dataJson}`);
    this.previousHash = entryHash;

    if (this.options.format === 'json') {
      return {
        id,
        timestamp: time,
        ...event,
        _hash: entryHash,
      };
    }

    // CloudEvents v1.0 format
    return {
      specversion: '1.0',
      id,
      type: event.type,
      source: this.source,
      time,
      datacontenttype: 'application/json',
      data: {
        tool: event.tool,
        arguments: this.sanitizeArguments(event.arguments),
        decision: event.decision,
        reason: event.reason,
        matched_rule: event.rule,
        mitigates: event.mitigates,
        latency_ms: event.latency_ms,
      },
      // Extension attributes for AgentMesh
      agentmeshversion: '1.0',
      entryhash: entryHash,
      previoushash: this.previousHash,
    };
  }

  private computeHash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  private sanitizeArguments(args?: Record<string, any>): Record<string, any> | undefined {
    if (!args) return undefined;

    // Redact potentially sensitive fields
    const sensitiveKeys = ['password', 'secret', 'token', 'key', 'credential', 'api_key'];
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(args)) {
      if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'string' && value.length > 500) {
        sanitized[key] = value.substring(0, 500) + '...[truncated]';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  close(): void {
    if (this.stream) {
      this.stream.end();
    }
  }
}
