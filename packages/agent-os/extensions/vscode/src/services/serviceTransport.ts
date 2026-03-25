// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Subprocess Transport
 *
 * Spawns a Python process to communicate with the Agent OS backend.
 * Each query spawns a short-lived process, writes JSON to stdin, and
 * reads JSON from stdout. Never throws -- all errors are returned as
 * ServiceResponse with ok: false.
 */

import { ChildProcess, spawn } from 'child_process';
import { ServiceTransport, ServiceResponse } from './serviceTypes';

/** Collected output from a child process. */
interface ProcessOutput {
    stdout: string;
    stderr: string;
    code: number | null;
}

/** Default query timeout in milliseconds. */
const TIMEOUT_MS = 5000;

/** Build an error response with duration tracking. */
function errorResponse<T>(error: string, startTime: number): ServiceResponse<T> {
    return {
        ok: false,
        data: undefined as unknown as T,
        error,
        durationMs: Date.now() - startTime,
    };
}

/**
 * Transport that spawns `python -m agent_os.extensions.vscode_bridge --json`
 * for each query. Writes a JSON payload to stdin and reads JSON from stdout.
 */
export class SubprocessTransport implements ServiceTransport {
    private readonly pythonPath: string;

    constructor(pythonPath: string = 'python') {
        this.pythonPath = pythonPath;
    }

    async query<T>(
        module: string,
        command: string,
        args?: Record<string, unknown>,
    ): Promise<ServiceResponse<T>> {
        const startTime = Date.now();
        const payload = JSON.stringify({ module, command, args: args ?? {} });
        const proc = this.spawnBridge(payload);

        try {
            const output = await this.collectOutput(proc);
            if (output.code !== 0) {
                const msg = output.stderr.trim() || `Process exited with code ${output.code}`;
                return errorResponse<T>(msg, startTime);
            }
            return this.parseStdout<T>(output.stdout, startTime);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'Unknown error';
            return errorResponse<T>(msg, startTime);
        }
    }

    /** Spawn the Python bridge process and write the payload. */
    private spawnBridge(payload: string): ChildProcess {
        const proc = spawn(
            this.pythonPath,
            ['-m', 'agent_os.extensions.vscode_bridge', '--json'],
            { stdio: ['pipe', 'pipe', 'pipe'] },
        );
        proc.stdin!.write(payload);
        proc.stdin!.end();
        return proc;
    }

    /** Collect stdout/stderr from process with timeout. */
    private collectOutput(proc: ChildProcess): Promise<ProcessOutput> {
        return new Promise<ProcessOutput>((resolve, reject) => {
            let stdout = '';
            let stderr = '';

            const timer = setTimeout(() => {
                proc.kill();
                reject(new Error('Query timed out'));
            }, TIMEOUT_MS);

            proc.stdout!.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
            proc.stderr!.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
            proc.on('error', (err: Error) => { clearTimeout(timer); reject(err); });
            proc.on('close', (code: number | null) => {
                clearTimeout(timer);
                resolve({ stdout, stderr, code });
            });
        });
    }

    async healthCheck(): Promise<boolean> {
        const res = await this.query('health', 'ping');
        return res.ok;
    }

    dispose(): void {
        // No persistent resources to clean up.
    }

    /** Parse stdout JSON into a ServiceResponse. */
    private parseStdout<T>(
        stdout: string,
        startTime: number,
    ): ServiceResponse<T> {
        const trimmed = stdout.trim();
        if (!trimmed) {
            return errorResponse('Empty response from backend', startTime);
        }
        try {
            const parsed = JSON.parse(trimmed) as ServiceResponse<T>;
            return {
                ok: parsed.ok ?? false,
                data: parsed.data as T,
                error: parsed.error,
                durationMs: Date.now() - startTime,
            };
        } catch {
            return errorResponse('Invalid JSON from backend', startTime);
        }
    }
}
