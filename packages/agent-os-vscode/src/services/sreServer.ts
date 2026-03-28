// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SRE Server Lifecycle Manager
 *
 * Manages a local agent-failsafe REST server subprocess.
 * Spawns on activation, health-checks, and kills on deactivation.
 * The extension owns the server lifecycle — no user setup required.
 */

import { ChildProcess, spawn } from 'child_process';
import axios from 'axios';

import * as vscode from 'vscode';

const DEFAULT_PORT = 9377;
const HEALTH_TIMEOUT_MS = 5000;
const HEALTH_RETRIES = 10;
const HEALTH_INTERVAL_MS = 500;

/** Result of attempting to start the SRE server. */
export interface ServerStartResult {
    /** Whether the server is running and healthy. */
    ok: boolean;
    /** Loopback endpoint URL if running, empty if not. */
    endpoint: string;
    /** Human-readable status message. */
    message: string;
}

/** Shell metacharacters that must not appear in a spawn() path argument. */
const SHELL_METACHAR = /[;&|`$(){}]/;

/**
 * Validate a Python path is non-empty and free of shell metacharacters.
 *
 * spawn() uses array args (no shell: true), so metacharacters cannot cause
 * injection — this regex is defense-in-depth. Null bytes are rejected to
 * prevent path truncation attacks on POSIX systems.
 */
export function isValidPythonPath(p: string): boolean {
    if (!p || !p.trim()) { return false; }
    if (SHELL_METACHAR.test(p)) { return false; }
    if (p.includes('\0')) { return false; }
    return true;
}

/**
 * Check if agent-failsafe is importable by the given Python interpreter.
 *
 * @param pythonPath - Path to Python executable
 * @returns true if agent_failsafe.rest_server is importable
 */
export async function isAgentFailsafeAvailable(pythonPath: string): Promise<boolean> {
    if (!isValidPythonPath(pythonPath)) { return false; }
    return new Promise((resolve) => {
        const proc = spawn(pythonPath, [
            '-c', 'import agent_failsafe.rest_server; print("ok")',
        ], { timeout: HEALTH_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'] });
        let output = '';
        proc.stdout?.on('data', (d: Buffer) => { output += d.toString(); });
        proc.on('close', (code) => { resolve(code === 0 && output.trim() === 'ok'); });
        proc.on('error', () => { resolve(false); });
    });
}

/**
 * Prompt the user to install agent-failsafe and run pip install.
 *
 * @param pythonPath - Path to Python executable
 * @returns true if installation succeeded
 */
export async function promptAndInstall(pythonPath: string): Promise<boolean> {
    const choice = await vscode.window.showInformationMessage(
        'agent-failsafe is not installed. Install it to enable live governance data?',
        'Install', 'Not Now',
    );
    if (choice !== 'Install') { return false; }

    return vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'Installing agent-failsafe...' },
        () => runPipInstall(pythonPath),
    );
}

function runPipInstall(pythonPath: string): Promise<boolean> {
    if (!isValidPythonPath(pythonPath)) { return Promise.resolve(false); }
    return new Promise((resolve) => {
        const proc = spawn(pythonPath, [
            '-m', 'pip', 'install', 'agent-failsafe[server]',
        ], { timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'] });

        let stderr = '';
        proc.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });
        proc.on('close', (code) => {
            if (code === 0) {
                vscode.window.showInformationMessage('agent-failsafe installed successfully.');
                resolve(true);
            } else {
                vscode.window.showErrorMessage(
                    `Failed to install agent-failsafe: ${stderr.slice(0, 200)}`,
                );
                resolve(false);
            }
        });
        proc.on('error', () => {
            vscode.window.showErrorMessage('Failed to run pip. Check your Python path.');
            resolve(false);
        });
    });
}

/**
 * Manages the lifecycle of a local agent-failsafe REST server.
 *
 * Spawns `python -m agent_failsafe.rest_server` as a child process,
 * waits for it to become healthy, and provides the loopback endpoint.
 */
export class SREServerManager {
    private _proc: ChildProcess | undefined;
    private _port: number;
    private _pythonPath: string;

    constructor(pythonPath: string, port?: number) {
        this._pythonPath = pythonPath.trim();
        this._port = port ?? DEFAULT_PORT;
    }

    /**
     * Start the REST server and wait for it to become healthy.
     *
     * @returns Result with endpoint URL if successful
     */
    async start(): Promise<ServerStartResult> {
        if (!isValidPythonPath(this._pythonPath)) {
            return { ok: false, endpoint: '', message: 'Invalid python path' };
        }
        const endpoint = `http://127.0.0.1:${this._port}`;

        // Check if something is already running on the port
        if (await this._isHealthy(endpoint)) {
            return { ok: true, endpoint, message: 'Server already running' };
        }

        this._proc = spawn(this._pythonPath, [
            '-m', 'agent_failsafe.rest_server',
        ], {
            stdio: ['ignore', 'ignore', 'ignore'],
            detached: false,
        });

        this._proc.on('error', () => { this._proc = undefined; });
        this._proc.on('exit', () => { this._proc = undefined; });

        // Wait for health check
        for (let i = 0; i < HEALTH_RETRIES; i++) {
            await this._sleep(HEALTH_INTERVAL_MS);
            if (!this._proc) {
                return { ok: false, endpoint: '', message: 'Server process exited unexpectedly' };
            }
            if (await this._isHealthy(endpoint)) {
                return { ok: true, endpoint, message: 'Server started' };
            }
        }

        this.stop();
        return { ok: false, endpoint: '', message: 'Server did not become healthy within timeout' };
    }

    /** Stop the server subprocess. */
    stop(): void {
        if (this._proc) {
            this._proc.kill();
            this._proc = undefined;
        }
    }

    /** Get the loopback endpoint URL. */
    getEndpoint(): string {
        return this._proc ? `http://127.0.0.1:${this._port}` : '';
    }

    private async _isHealthy(endpoint: string): Promise<boolean> {
        try {
            const res = await axios.get(`${endpoint}/sre/snapshot`, {
                timeout: 2000, maxRedirects: 0,
            });
            return res.status === 200;
        } catch {
            return false;
        }
    }

    private _sleep(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
