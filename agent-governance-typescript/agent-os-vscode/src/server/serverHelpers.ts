// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Server Helper Functions
 *
 * Utility functions for the governance server including port detection
 * and client ID generation.
 */

import * as http from 'http';
import { randomBytes } from 'crypto';

/** Default host for the governance server — bound to loopback only. */
export const DEFAULT_HOST = '127.0.0.1';

/** Default port to attempt binding. */
export const DEFAULT_PORT = 9845;

/**
 * Check if a specific port is available for binding.
 *
 * @param port - Port number to check
 * @param host - Host to bind to
 * @returns Promise resolving to true if port is available
 */
export function isPortAvailable(port: number, host: string): Promise<boolean> {
    return new Promise((resolve) => {
        const testServer = http.createServer();
        testServer.once('error', () => resolve(false));
        testServer.once('listening', () => {
            testServer.close(() => resolve(true));
        });
        testServer.listen(port, host);
    });
}

/**
 * Find an available port starting from the preferred one.
 * Tries up to 10 consecutive ports.
 *
 * @param startPort - Preferred port to start searching from
 * @param host - Host to bind to
 * @returns Promise resolving to the first available port
 */
export async function findAvailablePort(
    startPort: number,
    host: string
): Promise<number> {
    for (let attempt = 0; attempt < 10; attempt++) {
        const port = startPort + attempt;
        const available = await isPortAvailable(port, host);
        if (available) {
            return port;
        }
    }
    throw new Error(`No available port found starting from ${startPort}`);
}

/**
 * Generate a unique client connection ID.
 *
 * @returns Unique string identifier for a client
 */
export function generateClientId(): string {
    return `client_${Date.now()}_${randomBytes(4).toString('hex')}`;
}

/**
 * Generate a cryptographically secure session token.
 *
 * @returns 32-character hex token
 */
// SECURITY: 128 bits of crypto.randomBytes for session auth. Transmitted via
// Sec-WebSocket-Protocol subprotocol header (not URL query string, to avoid logging).
export function generateSessionToken(): string {
    return randomBytes(16).toString('hex');
}

/**
 * Generate a random nonce for Content-Security-Policy inline script allowlisting.
 *
 * @returns 32-character hex nonce
 */
export function generateNonce(): string {
    return randomBytes(16).toString('hex');
}

/** Rate limit record for a single IP. */
export interface RateLimitRecord {
    count: number;
    resetAt: number;
}

/**
 * Check if an IP has exceeded the rate limit (100 requests per minute).
 * Evicts stale entries on each call to prevent unbounded Map growth.
 *
 * @param ip - Client IP address
 * @param requestCounts - Map tracking per-IP request counts
 * @returns true if the request is allowed
 */
export function checkRateLimit(
    ip: string,
    requestCounts: Map<string, RateLimitRecord>
): boolean {
    const now = Date.now();
    const windowMs = 60_000;
    const maxRequests = 100;

    // Evict stale entries to prevent unbounded memory growth
    for (const [key, rec] of requestCounts) {
        if (now > rec.resetAt) { requestCounts.delete(key); }
    }

    const record = requestCounts.get(ip);
    if (!record || now > record.resetAt) {
        requestCounts.set(ip, { count: 1, resetAt: now + windowMs });
        return true;
    }
    if (record.count >= maxRequests) {
        return false;
    }
    record.count++;
    return true;
}

/**
 * Validate a session token from a WebSocket upgrade request.
 *
 * Uses the Sec-WebSocket-Protocol header (subprotocol negotiation) instead
 * of URL query strings. Query strings can leak into proxy logs, browser
 * history, and debug tools. Subprotocol headers are not logged by default.
 *
 * Client sends: `new WebSocket(url, ['governance-v1', token])`
 * Server validates the second protocol value against the expected token.
 *
 * @param req - Incoming HTTP request (from ws connection event)
 * @param expectedToken - The expected session token
 * @returns true if the token matches
 */
export function validateWebSocketToken(
    req: unknown,
    expectedToken: string,
): boolean {
    try {
        const incomingReq = req as { headers?: Record<string, string | string[] | undefined> };
        const protocolHeader = incomingReq?.headers?.['sec-websocket-protocol'];
        if (!protocolHeader) { return false; }
        // Header value is comma-separated: "governance-v1, <token>"
        const protocols = (typeof protocolHeader === 'string' ? protocolHeader : protocolHeader[0] ?? '')
            .split(',').map(s => s.trim());
        return protocols.includes(expectedToken);
    } catch {
        return false;
    }
}

/** Minimal WebSocket interface for type safety without importing ws types. */
export interface WebSocketLike {
    /** WebSocket ready state (1 = OPEN). */
    readyState: number;
    /** Send data to the client. */
    send(data: string): void;
    /** Close the connection with optional code and reason. */
    close(code?: number, reason?: string): void;
    /** Register event listener. */
    on(event: string, listener: (...args: unknown[]) => void): void;
}

/** Minimal WebSocket server interface. */
export interface WebSocketServerLike {
    /** Set of connected clients. */
    clients?: Set<WebSocketLike>;
    /** Register connection event listener. */
    on(event: string, listener: (ws: WebSocketLike, req: unknown) => void): void;
    /** Close the server. */
    close(callback?: () => void): void;
}
