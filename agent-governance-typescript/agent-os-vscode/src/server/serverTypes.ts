// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Server Types for Local Dev Server
 *
 * Type definitions for the governance dashboard local development server.
 * Enables browser-based viewing of SLO, topology, and audit dashboards.
 */

/** Configuration options for the local dev server. */
export interface ServerConfig {
    /** Default port to attempt binding (fallback to next available). */
    defaultPort: number;
    /** Host to bind the server to (typically localhost). */
    host: string;
}

/** Represents a connected WebSocket client. */
export interface ClientConnection {
    /** Unique identifier for this client connection. */
    id: string;
    /** Timestamp when the client connected. */
    connectedAt: Date;
}

/** Current state of the governance server. */
export interface ServerState {
    /** Port the server is currently listening on. */
    port: number;
    /** Full URL to access the dashboard. */
    url: string;
    /** List of currently connected WebSocket clients. */
    clients: ClientConnection[];
}

/** Message types sent to browser clients via WebSocket. */
export type ServerMessageType = 'sloUpdate' | 'topologyUpdate' | 'auditUpdate' | 'policyUpdate';

/** WebSocket message payload structure. */
export interface ServerMessage {
    /** Type of the message for client routing. */
    type: ServerMessageType;
    /** Message payload (varies by type). */
    data: unknown;
    /** ISO timestamp of when the message was sent. */
    timestamp: string;
}
