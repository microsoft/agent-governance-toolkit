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
  const openAiTokenFixture = `sk-FAKEFORTESTING${'x'.repeat(20)}`;
  const awsKeyFixture = `AKIA${'A'.repeat(16)}`;
  const googleKeyFixture = `AIza${'A'.repeat(35)}`;

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
        embeddedToken: 'github_pat_FAKE_FOR_TESTING_0000000000000000000000',
        openAiToken: openAiTokenFixture,
        slackToken: 'xoxb-FAKE-FOR-TESTING-0000000000',
        nested: {
          note: '-----BEGIN DSA PRIVATE KEY-----\nZmFrZQ==\n-----END DSA PRIVATE KEY-----',
          cloud: [awsKeyFixture, googleKeyFixture],
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

    expect(entry.data.arguments.embeddedToken).toBe('[REDACTED]');
    expect(entry.data.arguments.openAiToken).toBe('[REDACTED]');
    expect(entry.data.arguments.slackToken).toBe('[REDACTED]');
    expect(entry.data.arguments.nested.note).toBe('[REDACTED]');
    expect(entry.data.arguments.nested.cloud).toEqual(['[REDACTED]', '[REDACTED]']);
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

  // -----------------------------------------------------------
  // Boundary regression tests for issue #3933
  // Credentials glued to _ must be redacted by sanitizeValue.
  // -----------------------------------------------------------

  it('redacts GitHub token glued to underscore on right edge', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: 'ghp_FAKEFORTESTING000000000000000000_old',
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

    expect(entry.arguments.config).not.toContain('ghp_FAKEFORTESTING');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });

  it('redacts AWS key glued to underscore on both edges', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: `env_${awsKeyFixture}_old`,
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

    expect(entry.arguments.config).not.toContain('AKIA');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });

  it('redacts Google API key glued to underscore on left edge', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: `svc_${googleKeyFixture}`,
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

    expect(entry.arguments.config).not.toContain('AIza');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });

  it('redacts OpenAI token glued to underscore on left edge', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: `session_${openAiTokenFixture}_bak`,
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

    expect(entry.arguments.config).not.toContain('sk-FAKEFORTESTING');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });

  it('redacts Google API key ending in hyphen when glued (superset branch, pinned)', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    // Google API key whose 35th value char is '-', followed by alnum.
    // The (?:(?![A-Za-z0-9])|(?<=-)) superset tail must still redact this.
    const googleKey = `AIza${'A'.repeat(34)}-X`;
    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: googleKey,
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

    expect(entry.arguments.config).not.toContain('AIza');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });

  it('redacts OpenAI token preceded by hyphen (left-edge widening, pinned)', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcp-proxy-audit-'));
    tempDirs.push(tempDir);

    const logPath = join(tempDir, 'audit.log');
    const logger = new AuditLogger({ path: logPath, format: 'json' });

    logger.log({
      type: 'ai.agentmesh.tool.invoked',
      tool: 'echo',
      decision: 'allow',
      arguments: {
        config: `my-${openAiTokenFixture}`,
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

    // Left-edge widening: hyphen-prefixed OpenAI keys ARE redacted,
    // aligned with the Python SDK's (?<![A-Za-z0-9]) anchor.
    expect(entry.arguments.config).not.toContain('sk-FAKEFORTESTING');
    expect(entry.arguments.config).toContain('[REDACTED]');
  });
});
