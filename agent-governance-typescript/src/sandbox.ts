// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

import { execSync, exec } from 'child_process';
import { randomUUID } from 'crypto';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export enum SessionStatus {
  Provisioning = 'provisioning',
  Ready = 'ready',
  Executing = 'executing',
  Destroying = 'destroying',
  Destroyed = 'destroyed',
  Failed = 'failed',
}

export enum ExecutionStatus {
  Pending = 'pending',
  Running = 'running',
  Completed = 'completed',
  Cancelled = 'cancelled',
  Failed = 'failed',
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

export interface SandboxConfig {
  timeoutSeconds: number;
  memoryMb: number;
  cpuLimit: number;
  networkEnabled: boolean;
  readOnlyFs: boolean;
  envVars: Record<string, string>;
}

export interface SandboxResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationSeconds: number;
  killed: boolean;
  killReason: string;
}

export interface SessionHandle {
  agentId: string;
  sessionId: string;
  status: SessionStatus;
}

export interface ExecutionHandle {
  executionId: string;
  agentId: string;
  sessionId: string;
  status: ExecutionStatus;
  result?: SandboxResult;
}

// ---------------------------------------------------------------------------
// Default config factory
// ---------------------------------------------------------------------------

export function defaultSandboxConfig(): SandboxConfig {
  return {
    timeoutSeconds: 60,
    memoryMb: 512,
    cpuLimit: 1.0,
    networkEnabled: false,
    readOnlyFs: true,
    envVars: {},
  };
}

// ---------------------------------------------------------------------------
// Abstract interface
// ---------------------------------------------------------------------------

export interface SandboxProvider {
  createSession(agentId: string, config?: SandboxConfig): Promise<SessionHandle>;
  executeCode(agentId: string, sessionId: string, code: string): Promise<ExecutionHandle>;
  destroySession(agentId: string, sessionId: string): Promise<void>;
  isAvailable(): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Environment variables blocked from sandbox containers
// ---------------------------------------------------------------------------

const BLOCKED_ENV_VARS = new Set([
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'LD_DEBUG',
  'LD_PROFILE',
  'LD_SHOW_AUXV',
  'LD_DYNAMIC_WEAK',
  'PYTHONSTARTUP',
  'PYTHONPATH',
]);

function sanitizeEnvVars(envVars: Record<string, string>): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(envVars)) {
    if (!BLOCKED_ENV_VARS.has(k.toUpperCase())) {
      clean[k] = v;
    }
  }
  return clean;
}

// Docker resource-name pattern: [a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}
const DOCKER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

function validateResourceName(value: string, label: string): void {
  if (!DOCKER_NAME_RE.test(value)) {
    throw new Error(
      `Invalid ${label} '${value}': must match [a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}`,
    );
  }
}

// ---------------------------------------------------------------------------
// DockerSandboxProvider
// ---------------------------------------------------------------------------

export class DockerSandboxProvider implements SandboxProvider {
  private readonly image: string;
  private readonly containers = new Map<string, string>(); // sessionId -> containerId

  constructor(image: string = 'python:3.11-slim') {
    this.image = image;
  }

  async isAvailable(): Promise<boolean> {
    try {
      execSync('docker info', { stdio: 'pipe', timeout: 10_000 });
      return true;
    } catch {
      return false;
    }
  }

  async createSession(
    agentId: string,
    config?: SandboxConfig,
  ): Promise<SessionHandle> {
    validateResourceName(agentId, 'agentId');

    const cfg = config ?? defaultSandboxConfig();
    const sessionId = randomUUID();
    const containerName = `agt-${agentId}-${sessionId.slice(0, 8)}`;

    const args: string[] = [
      'docker', 'run', '-d',
      '--name', containerName,
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      `--memory=${cfg.memoryMb}m`,
      `--cpus=${cfg.cpuLimit}`,
      '--pids-limit=256',
    ];

    if (cfg.readOnlyFs) {
      args.push('--read-only');
    }

    if (!cfg.networkEnabled) {
      args.push('--network=none');
    }

    const safeEnv = sanitizeEnvVars(cfg.envVars);
    for (const [k, v] of Object.entries(safeEnv)) {
      args.push('-e', `${k}=${v}`);
    }

    args.push(this.image, 'tail', '-f', '/dev/null');

    try {
      const containerId = execSync(args.join(' '), {
        stdio: 'pipe',
        timeout: 30_000,
      })
        .toString()
        .trim();

      this.containers.set(sessionId, containerId);

      return {
        agentId,
        sessionId,
        status: SessionStatus.Ready,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to create sandbox session: ${message}`);
    }
  }

  async executeCode(
    agentId: string,
    sessionId: string,
    code: string,
  ): Promise<ExecutionHandle> {
    validateResourceName(agentId, 'agentId');

    const containerId = this.containers.get(sessionId);
    if (!containerId) {
      throw new Error(`No active session '${sessionId}' for agent '${agentId}'`);
    }

    const executionId = randomUUID();
    const startTime = Date.now();

    return new Promise<ExecutionHandle>((resolve) => {
      const encoded = Buffer.from(code).toString('base64');
      const cmd = `docker exec ${containerId} python3 -c "import base64; exec(base64.b64decode('${encoded}').decode())"`;

      exec(cmd, { timeout: 60_000 }, (error, stdout, stderr) => {
        const durationSeconds = (Date.now() - startTime) / 1000.0;
        const exitCode = error && 'code' in error ? (error.code as number ?? 1) : 0;
        const killed = error !== null && 'killed' in error && (error as { killed: boolean }).killed;

        const result: SandboxResult = {
          success: exitCode === 0,
          exitCode,
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          durationSeconds,
          killed,
          killReason: killed ? 'timeout' : '',
        };

        resolve({
          executionId,
          agentId,
          sessionId,
          status: exitCode === 0 ? ExecutionStatus.Completed : ExecutionStatus.Failed,
          result,
        });
      });
    });
  }

  async destroySession(agentId: string, sessionId: string): Promise<void> {
    validateResourceName(agentId, 'agentId');

    const containerId = this.containers.get(sessionId);
    if (!containerId) {
      return; // already destroyed or never existed
    }

    try {
      execSync(`docker rm -f ${containerId}`, {
        stdio: 'pipe',
        timeout: 15_000,
      });
    } finally {
      this.containers.delete(sessionId);
    }
  }
}
