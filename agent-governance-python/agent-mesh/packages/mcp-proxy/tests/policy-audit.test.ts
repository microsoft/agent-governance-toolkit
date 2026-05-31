// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, expect, it } from 'vitest';
import { once } from 'events';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { AuditLogger } from '../src/audit.js';
import { evaluatePolicy, Policy } from '../src/policy.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('evaluatePolicy', () => {
  it('copies mitigates from the matched rule into the decision', () => {
    const policy: Policy = {
      version: '1.0',
      mode: 'enforce',
      rules: [
        {
          tool: 'run_shell',
          action: 'deny',
          reason: 'blocked',
          mitigates: ['ASI02', 'ASI05'],
        },
        { tool: '*', action: 'allow' },
      ],
    };

    const decision = evaluatePolicy(policy, 'run_shell', {});

    expect(decision).toMatchObject({
      allowed: false,
      matchedRule: 'run_shell',
      mitigatedRisks: ['ASI02', 'ASI05'],
    });
  });

  it('leaves mitigatedRisks unset when the matched rule has no annotations', () => {
    const policy: Policy = {
      version: '1.0',
      mode: 'enforce',
      rules: [{ tool: '*', action: 'allow' }],
    };

    const decision = evaluatePolicy(policy, 'read_file', { path: 'README.md' });

    expect(decision.allowed).toBe(true);
    expect(decision.mitigatedRisks).toBeUndefined();
  });
});

describe('AuditLogger', () => {
  it('includes mitigates in CloudEvents data only when present', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath });

    logger.log({
      type: 'ai.agentmesh.policy.violation',
      tool: 'run_shell',
      decision: 'deny',
      mitigates: ['ASI02', 'ASI05'],
    });
    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'read_file',
      decision: 'allow',
    });

    logger.close();

    const stream = Reflect.get(logger, 'stream');
    if (stream) {
      await once(stream, 'finish');
    }

    const [deniedEntry, allowedEntry] = readFileSync(logPath, 'utf-8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { data: Record<string, unknown> });

    expect(deniedEntry.data.mitigates).toEqual(['ASI02', 'ASI05']);
    expect(allowedEntry.data).not.toHaveProperty('mitigates');
  });

  it('redacts credential-looking values in CloudEvents arguments', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        publicField: 'github_pat_FAKE_FOR_TESTING_0000000000000000000000',
        nested: {
          note: '-----BEGIN DSA PRIVATE KEY-----\nZmFrZQ==\n-----END DSA PRIVATE KEY-----',
        },
      },
    });

    logger.close();

    const stream = Reflect.get(logger, 'stream');
    if (stream) {
      await once(stream, 'finish');
    }

    const [entry] = readFileSync(logPath, 'utf-8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { data: { arguments: Record<string, any> } });

    expect(entry.data.arguments.publicField).toBe('[REDACTED]');
    expect(entry.data.arguments.nested.note).toBe('[REDACTED]');
  });

  it('redacts arguments in plain json audit format', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        publicField: 'gho_FAKEFORTESTING000000000000000000',
      },
    });

    logger.close();

    const stream = Reflect.get(logger, 'stream');
    if (stream) {
      await once(stream, 'finish');
    }

    const entry = JSON.parse(readFileSync(logPath, 'utf-8').trim()) as {
      arguments: Record<string, unknown>;
    };

    expect(entry.arguments.publicField).toBe('[REDACTED]');
  });
});
