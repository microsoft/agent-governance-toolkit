// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

import {
  defaultSandboxConfig,
  DockerSandboxProvider,
  SessionStatus,
  ExecutionStatus,
} from '../src/sandbox';

describe('defaultSandboxConfig', () => {
  it('returns expected default values', () => {
    const cfg = defaultSandboxConfig();
    expect(cfg.timeoutSeconds).toBe(60);
    expect(cfg.memoryMb).toBe(512);
    expect(cfg.cpuLimit).toBe(1.0);
    expect(cfg.networkEnabled).toBe(false);
    expect(cfg.readOnlyFs).toBe(true);
    expect(cfg.envVars).toEqual({});
  });

  it('returns a fresh object each call', () => {
    const a = defaultSandboxConfig();
    const b = defaultSandboxConfig();
    expect(a).not.toBe(b);
    a.envVars['FOO'] = 'bar';
    expect(b.envVars).toEqual({});
  });
});

describe('DockerSandboxProvider', () => {
  it('uses default image python:3.11-slim', () => {
    const provider = new DockerSandboxProvider();
    expect(provider).toBeDefined();
    // Verify it's an instance implementing SandboxProvider
    expect(typeof provider.createSession).toBe('function');
    expect(typeof provider.executeCode).toBe('function');
    expect(typeof provider.destroySession).toBe('function');
    expect(typeof provider.isAvailable).toBe('function');
  });

  it('accepts a custom image', () => {
    const provider = new DockerSandboxProvider('node:20-slim');
    expect(provider).toBeDefined();
  });

  it('isAvailable handles missing Docker gracefully', async () => {
    const provider = new DockerSandboxProvider();
    // Should not throw — returns boolean regardless of Docker presence
    const result = await provider.isAvailable();
    expect(typeof result).toBe('boolean');
  });
});

describe('SessionStatus enum', () => {
  it('has expected members', () => {
    expect(SessionStatus.Provisioning).toBe('provisioning');
    expect(SessionStatus.Ready).toBe('ready');
    expect(SessionStatus.Executing).toBe('executing');
    expect(SessionStatus.Destroying).toBe('destroying');
    expect(SessionStatus.Destroyed).toBe('destroyed');
    expect(SessionStatus.Failed).toBe('failed');
  });
});

describe('ExecutionStatus enum', () => {
  it('has expected members', () => {
    expect(ExecutionStatus.Pending).toBe('pending');
    expect(ExecutionStatus.Running).toBe('running');
    expect(ExecutionStatus.Completed).toBe('completed');
    expect(ExecutionStatus.Cancelled).toBe('cancelled');
    expect(ExecutionStatus.Failed).toBe('failed');
  });
});

// Full lifecycle test — skip when Docker is not available
describe('DockerSandboxProvider lifecycle', () => {
  let provider: DockerSandboxProvider;
  let dockerAvailable: boolean;

  beforeAll(async () => {
    provider = new DockerSandboxProvider();
    dockerAvailable = await provider.isAvailable();
  });

  it('creates, executes, and destroys a session', async () => {
    if (!dockerAvailable) {
      console.log('Skipping lifecycle test — Docker not available');
      return;
    }

    // Create session
    const session = await provider.createSession('testAgent');
    expect(session.agentId).toBe('testAgent');
    expect(session.sessionId).toBeTruthy();
    expect(session.status).toBe(SessionStatus.Ready);

    try {
      // Execute code
      const handle = await provider.executeCode(
        'testAgent',
        session.sessionId,
        'print("hello sandbox")',
      );
      expect(handle.executionId).toBeTruthy();
      expect(handle.agentId).toBe('testAgent');
      expect(handle.sessionId).toBe(session.sessionId);
      expect(handle.status).toBe(ExecutionStatus.Completed);
      expect(handle.result).toBeDefined();
      expect(handle.result!.success).toBe(true);
      expect(handle.result!.stdout.trim()).toBe('hello sandbox');
      expect(handle.result!.exitCode).toBe(0);
      expect(handle.result!.durationSeconds).toBeGreaterThan(0);
    } finally {
      // Always clean up
      await provider.destroySession('testAgent', session.sessionId);
    }
  }, 60_000);

  it('destroySession is idempotent', async () => {
    if (!dockerAvailable) {
      console.log('Skipping idempotent test — Docker not available');
      return;
    }

    // Destroying a non-existent session should not throw
    await expect(
      provider.destroySession('testAgent', 'nonexistent-id'),
    ).resolves.toBeUndefined();
  });

  it('executeCode rejects for unknown session', async () => {
    await expect(
      provider.executeCode('testAgent', 'nonexistent-id', 'print("hi")'),
    ).rejects.toThrow(/No active session/);
  });
});
