// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Regression tests for issue #3118: DockerSandboxProvider.executeCode() must
// honour the session's configured timeoutSeconds rather than a hard-coded
// 60_000 ms. child_process is mocked so these run without Docker.

import { execFile, execFileSync } from 'child_process';
import { DockerSandboxProvider, defaultSandboxConfig } from '../src/sandbox';

jest.mock('child_process');

const mockedExecFileSync = execFileSync as jest.MockedFunction<typeof execFileSync>;
const mockedExecFile = execFile as unknown as jest.Mock;

describe('DockerSandboxProvider executeCode timeout (issue #3118)', () => {
  let capturedTimeoutMs: number | undefined;

  beforeEach(() => {
    capturedTimeoutMs = undefined;
    // createSession -> execFileSync('docker', ['run', ...]) returns the container id.
    mockedExecFileSync.mockReturnValue(Buffer.from('fake-container-id'));
    // executeCode -> execFile('docker', ['exec', ...], options, cb). Capture the
    // timeout and report a clean, successful execution.
    mockedExecFile.mockImplementation(
      (
        _file: string,
        _args: string[],
        options: { timeout?: number },
        cb: (error: null, stdout: string, stderr: string) => void,
      ) => {
        capturedTimeoutMs = options.timeout;
        cb(null, '', '');
        return {} as never;
      },
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('uses the session-configured timeoutSeconds', async () => {
    const provider = new DockerSandboxProvider();
    const config = { ...defaultSandboxConfig(), timeoutSeconds: 2 };
    const session = await provider.createSession('agent', config);

    await provider.executeCode('agent', session.sessionId, 'print("hi")');

    expect(capturedTimeoutMs).toBe(2000);
  });

  it('does not hard-code 60_000 ms for a custom timeout', async () => {
    const provider = new DockerSandboxProvider();
    const config = { ...defaultSandboxConfig(), timeoutSeconds: 5 };
    const session = await provider.createSession('agent', config);

    await provider.executeCode('agent', session.sessionId, 'print("hi")');

    expect(capturedTimeoutMs).toBe(5000);
    expect(capturedTimeoutMs).not.toBe(60_000);
  });

  it('falls back to the default timeout when no config is provided', async () => {
    const provider = new DockerSandboxProvider();
    const session = await provider.createSession('agent');

    await provider.executeCode('agent', session.sessionId, 'print("hi")');

    expect(capturedTimeoutMs).toBe(defaultSandboxConfig().timeoutSeconds * 1000);
  });

  // A non-positive timeoutSeconds must not become `timeout: 0`, which Node's
  // execFile treats as "no timeout" and would disable the sandbox safety cap.
  it('clamps a non-positive timeoutSeconds to the default', async () => {
    const provider = new DockerSandboxProvider();
    const config = { ...defaultSandboxConfig(), timeoutSeconds: 0 };
    const session = await provider.createSession('agent', config);

    await provider.executeCode('agent', session.sessionId, 'print("hi")');

    expect(capturedTimeoutMs).toBe(defaultSandboxConfig().timeoutSeconds * 1000);
    expect(capturedTimeoutMs).not.toBe(0);
  });

  it('clamps a non-finite timeoutSeconds to the default', async () => {
    const provider = new DockerSandboxProvider();
    // Simulate a value that arrived via `any` and bypassed static typing.
    const config = { ...defaultSandboxConfig(), timeoutSeconds: NaN as number };
    const session = await provider.createSession('agent', config);

    await provider.executeCode('agent', session.sessionId, 'print("hi")');

    expect(capturedTimeoutMs).toBe(defaultSandboxConfig().timeoutSeconds * 1000);
    expect(Number.isFinite(capturedTimeoutMs)).toBe(true);
  });
});
