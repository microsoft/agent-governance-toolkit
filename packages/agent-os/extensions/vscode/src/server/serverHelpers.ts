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

/** Minimal WebSocket interface for type safety without importing ws types. */
export interface WebSocketLike {
    /** WebSocket ready state (1 = OPEN). */
    readyState: number;
    /** Send data to the client. */
    send(data: string): void;
    /** Register event listener. */
    on(event: string, listener: () => void): void;
}

/** Minimal WebSocket server interface. */
export interface WebSocketServerLike {
    /** Set of connected clients. */
    clients?: Set<WebSocketLike>;
    /** Register connection event listener. */
    on(event: string, listener: (ws: WebSocketLike) => void): void;
    /** Close the server. */
    close(callback?: () => void): void;
}
