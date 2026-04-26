// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Live SRE Client
 *
 * HTTP client that polls agent-failsafe REST endpoints and caches
 * the latest snapshot. Tracks staleness and escalates to per-endpoint
 * fetching when response latency exceeds a threshold.
 */

import * as vscode from 'vscode';
import axios, { AxiosInstance } from 'axios';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for the live SRE client. */
export interface SREClientOptions {
    /** Base URL of agent-failsafe REST server (e.g. "http://127.0.0.1:9377"). */
    endpoint: string;
    /** Polling interval in ms. Clamped to minimum 5000. */
    refreshIntervalMs?: number;
    /** Latency threshold (ms) that triggers per-endpoint escalation. */
    escalationLatencyMs?: number;
    /** Bearer token for Authorization header (optional). */
    token?: string;
}

/** Cached response with staleness tracking. */
export interface CachedSnapshot {
    /** Raw JSON from /sre/snapshot (or null if never fetched). */
    data: Record<string, unknown> | null;
    /** When the last successful fetch completed. */
    lastUpdatedAt: Date | null;
    /** Human-readable error from the most recent failure (null if healthy). */
    error: string | null;
    /** True when data is absent or the last fetch failed. */
    stale: boolean;
    /** True when the client has escalated to per-endpoint fetching. */
    escalated: boolean;
}

const MIN_INTERVAL_MS = 5000;
const REQUEST_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB
const ESCALATION_WINDOW = 5;
const DE_ESCALATION_WINDOW = 10;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/**
 * Validate that an endpoint URL targets a loopback address.
 *
 * @param endpoint - URL to validate
 * @returns true if the hostname is a loopback address
 */
export function isLoopbackEndpoint(endpoint: string): boolean {
    try {
        const url = new URL(endpoint);
        return LOOPBACK_HOSTS.has(url.hostname);
    } catch {
        return false;
    }
}

/** Polls agent-failsafe REST endpoints and caches the latest snapshot. */
export class LiveSREClient {
    private _http: AxiosInstance;
    private _timer: ReturnType<typeof setInterval> | undefined;
    private _cache: CachedSnapshot;
    private _intervalMs: number;
    private _escalationMs: number;
    private _latencies: number[] = [];
    private _consecutiveFast = 0;
    private _polling = false;
    private _disposed = false;
    private readonly _onDidChange = new vscode.EventEmitter<void>();

    /** Fires after each successful poll that updates the cache. */
    readonly onDidChange: vscode.Event<void> = this._onDidChange.event;

    constructor(private readonly _options: SREClientOptions) {
        if (!isLoopbackEndpoint(_options.endpoint)) {
            throw new Error('Governance endpoint must target a loopback address (127.0.0.1, localhost, ::1)');
        }
        this._intervalMs = Math.max(_options.refreshIntervalMs ?? 10_000, MIN_INTERVAL_MS);
        this._escalationMs = _options.escalationLatencyMs ?? 2000;
        this._http = axios.create({
            baseURL: _options.endpoint,
            timeout: REQUEST_TIMEOUT_MS,
            maxContentLength: MAX_RESPONSE_BYTES,
            maxBodyLength: MAX_RESPONSE_BYTES,
            maxRedirects: 0,
            headers: _options.token
                ? { Authorization: `Bearer ${_options.token}` }
                : {},
        });
        this._cache = { data: null, lastUpdatedAt: null, error: null, stale: true, escalated: false };
    }

    /** Start polling. First fetch is immediate. */
    start(): void {
        if (this._timer) { return; }
        this._poll();
        this._timer = setInterval(() => this._poll(), this._intervalMs);
    }

    /** Stop polling and release resources. */
    dispose(): void {
        this._disposed = true;
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = undefined;
        }
        this._onDidChange.dispose();
    }

    /** Get the current cached snapshot (read-only). */
    getSnapshot(): Readonly<CachedSnapshot> {
        return this._cache;
    }

    /** Update the auth token for subsequent requests. */
    setToken(token: string | undefined): void {
        if (token) {
            this._http.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
            delete this._http.defaults.headers.common['Authorization'];
        }
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    private async _poll(): Promise<void> {
        if (this._polling) { return; }
        this._polling = true;
        const start = Date.now();
        try {
            const data = this._cache.escalated
                ? await this._fetchPerEndpoint()
                : await this._fetchSnapshot();
            const latency = Date.now() - start;
            this._cache = { data, lastUpdatedAt: new Date(), error: null, stale: false, escalated: this._cache.escalated };
            this._trackLatency(latency);
            if (!this._disposed) { this._onDidChange.fire(); }
        } catch (err: unknown) {
            this._cache = { ...this._cache, error: _sanitizeError(err), stale: true };
        } finally {
            this._polling = false;
        }
    }

    private async _fetchSnapshot(): Promise<Record<string, unknown>> {
        const res = await this._http.get('/sre/snapshot');
        if (typeof res.data !== 'object' || res.data === null) {
            throw new Error('Invalid response: not an object');
        }
        return res.data as Record<string, unknown>;
    }

    private async _fetchPerEndpoint(): Promise<Record<string, unknown>> {
        const [snapshot, fleet, events] = await Promise.all([
            this._http.get('/sre/snapshot').then(r => r.data).catch(() => ({})),
            this._http.get('/sre/fleet').then(r => r.data).catch(() => ({ agents: [] })),
            this._http.get('/sre/events').then(r => r.data).catch(() => ({ events: [] })),
        ]);
        return { ...snapshot, fleet: fleet?.agents ?? [], auditEvents: events?.events ?? [] };
    }

    private _trackLatency(ms: number): void {
        this._latencies.push(ms);
        if (this._latencies.length > ESCALATION_WINDOW) {
            this._latencies.shift();
        }
        const avg = this._latencies.reduce((a, b) => a + b, 0) / this._latencies.length;

        if (!this._cache.escalated && this._latencies.length >= ESCALATION_WINDOW && avg > this._escalationMs) {
            this._cache = { ...this._cache, escalated: true };
            this._consecutiveFast = 0;
        } else if (this._cache.escalated && ms < this._escalationMs) {
            this._consecutiveFast++;
            if (this._consecutiveFast >= DE_ESCALATION_WINDOW) {
                this._cache = { ...this._cache, escalated: false };
                this._latencies = [];
                this._consecutiveFast = 0;
            }
        } else {
            this._consecutiveFast = 0;
        }
    }
}

/** Classify an error into a safe, fixed message. Never expose URLs or headers. */
function _sanitizeError(err: unknown): string {
    if (!err || typeof err !== 'object') { return 'Unknown error'; }
    const axiosErr = err as { code?: string; response?: { status?: number } };
    if (axiosErr.code === 'ECONNREFUSED') { return 'Connection refused'; }
    if (axiosErr.code === 'ECONNABORTED') { return 'Request timeout'; }
    if (axiosErr.code === 'ERR_NETWORK') { return 'Network error'; }
    if (axiosErr.response?.status) { return `Server error (${axiosErr.response.status})`; }
    return 'Connection failed';
}
