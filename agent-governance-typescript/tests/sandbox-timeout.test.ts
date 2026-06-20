// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

import { EventEmitter } from 'events';
import * as childProcess from 'child_process';

jest.mock('child_process');

import { DockerSandboxProvider, defaultSandboxConfig } from '../src/sandbox';

const mockedExecFileSync = childProcess.execFileSync as jest.Mock;
const mockedExecFile = childProcess.execFile as unknown as jest.Mock;

// Regression coverage for the timeout wiring. These run without Docker by
// stubbing child_process: createSession's `docker run` returns a container id,
// and executeCode's `docker exec` completes immediately so we can inspect the
// options passed to it.
describe('DockerSandboxProvider timeout enforcement', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedExecFileSync.mockReturnValue(Buffer.from('container-abc123\n'));
    mockedExecFile.mockImplementation((_cmd, _args, _options, cb) => {
      cb(null, '', '');
      return new EventEmitter();
    });
  });

  it('passes the configured timeout to docker exec', async () => {
    const provider = new DockerSandboxProvider();
    const config = { ...defaultSandboxConfig(), timeoutSeconds: 2 };

    const session = await provider.createSession('testAgent', config);
    await provider.executeCode('testAgent', session.sessionId, 'print("hi")');

    expect(mockedExecFile).toHaveBeenCalledTimes(1);
    const options = mockedExecFile.mock.calls[0][2];
    expect(options).toMatchObject({ timeout: 2000 });
  });

  it('falls back to the default 60s timeout when no config is given', async () => {
    const provider = new DockerSandboxProvider();

    const session = await provider.createSession('testAgent');
    await provider.executeCode('testAgent', session.sessionId, 'print("hi")');

    const options = mockedExecFile.mock.calls[0][2];
    expect(options).toMatchObject({ timeout: 60_000 });
  });
});
