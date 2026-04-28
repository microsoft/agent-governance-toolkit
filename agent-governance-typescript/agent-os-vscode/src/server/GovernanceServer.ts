// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Server
 *
 * Local development server for browser-based governance dashboard viewing.
 * Uses Node's built-in http module and ws package for WebSocket support.
 * Broadcasts SLO, topology, and audit updates to all connected clients.
 */

import * as http from 'http';
import * as path from 'path';
import { SLODataProvider } from '../views/sloTypes';
import { AgentTopologyDataProvider } from '../views/topologyTypes';
import { PolicyDataProvider } from '../views/policyTypes';
import { AuditLogger } from '../auditLogger';
import { ServerState, ClientConnection, ServerMessage, ServerMessageType } from './serverTypes';
import { renderBrowserDashboard } from './browserTemplate';
import {
    DEFAULT_HOST,
    DEFAULT_PORT,
    findAvailablePort,
    generateClientId,
    generateSessionToken,
    generateNonce,
    checkRateLimit,
    validateWebSocketToken,
    RateLimitRecord,
    WebSocketLike,
    WebSocketServerLike
} from './serverHelpers';

/**
 * Local development server for governance dashboard visualization.
 *
 * Serves an HTML dashboard accessible via browser and pushes real-time
 * updates to connected WebSocket clients. Uses singleton pattern to
 * ensure only one server instance runs at a time.
 */
export class GovernanceServer {

    private static _instance: GovernanceServer | undefined;

    private _httpServer: http.Server | undefined;
    private _wsServer: WebSocketServerLike | undefined;
    private _clients: Map<string, ClientConnection> = new Map();
    private _port: number = 0;
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;
    private _sessionToken: string = '';
    private _requestCounts: Map<string, RateLimitRecord> = new Map();

    private constructor(
        private readonly _sloProvider: SLODataProvider,
        private readonly _topologyProvider: AgentTopologyDataProvider,
        private readonly _auditLogger: AuditLogger,
        private readonly _policyProvider?: PolicyDataProvider,
    ) {}

    /** Get or create the singleton server instance. */
    public static getInstance(
        sloProvider: SLODataProvider,
        topologyProvider: AgentTopologyDataProvider,
        auditLogger: AuditLogger,
        policyProvider?: PolicyDataProvider,
    ): GovernanceServer {
        if (!GovernanceServer._instance) {
            GovernanceServer._instance = new GovernanceServer(
                sloProvider,
                topologyProvider,
                auditLogger,
                policyProvider,
            );
        }
        return GovernanceServer._instance;
    }

    /**
     * Start the server on the specified or default port.
     * Automatically finds an available port if the default is occupied.
     */
    public async start(port?: number): Promise<number> {
        if (this._httpServer) {
            return this._port;
        }
        this._port = await findAvailablePort(port ?? DEFAULT_PORT, DEFAULT_HOST);
        // SECURITY: Session token via Sec-WebSocket-Protocol subprotocol header.
        // Avoids query string logging by proxies/debug tools. Server binds to 127.0.0.1 only.
        this._sessionToken = generateSessionToken();
        await this._createHttpServer();
        await this._createWebSocketServer();
        this._refreshInterval = setInterval(() => this._broadcastUpdates(), 10_000);
        return this._port;
    }

    /** Stop the server and clean up all resources. */
    public async stop(): Promise<void> {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }
        this._requestCounts.clear();
        await this._closeServer(this._wsServer, () => {
            this._wsServer = undefined;
            this._clients.clear();
        });
        await this._closeServer(this._httpServer, () => {
            this._httpServer = undefined;
        });
        GovernanceServer._instance = undefined;
    }

    /** Get the URL for accessing the dashboard. */
    public getUrl(): string {
        return `http://${DEFAULT_HOST}:${this._port}`;
    }

    /** Get the session token for WebSocket authentication. */
    public getSessionToken(): string {
        return this._sessionToken;
    }

    /** Get the current server state. */
    public getState(): ServerState {
        return {
            port: this._port,
            url: this.getUrl(),
            clients: Array.from(this._clients.values())
        };
    }

    /** Broadcast a message to all connected WebSocket clients. */
    public broadcast(type: ServerMessageType, data: unknown): void {
        const message: ServerMessage = {
            type,
            data,
            timestamp: new Date().toISOString()
        };
        const payload = JSON.stringify(message);
        this._wsServer?.clients?.forEach((client: WebSocketLike) => {
            if (client.readyState === 1) {
                client.send(payload);
            }
        });
    }

    /** Create and start the HTTP server. */
    private _createHttpServer(): Promise<void> {
        return new Promise((resolve, reject) => {
            this._httpServer = http.createServer((req, res) => {
                this._handleRequest(req, res);
            });
            this._httpServer.once('error', reject);
            // SECURITY: Loopback binding prevents external access. Validated by DEFAULT_HOST = '127.0.0.1'.
            this._httpServer.listen(this._port, DEFAULT_HOST, () => resolve());
        });
    }

    /** Handle incoming HTTP requests. */
    private _handleRequest(
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): void {
        const ip = req.socket.remoteAddress || 'unknown';
        // SECURITY: Rate limiter Map without TTL eviction. Loopback-only = at most 1 entry.
        if (!checkRateLimit(ip, this._requestCounts)) {
            res.writeHead(429, { 'Retry-After': '60' });
            res.end('Rate limit exceeded');
            return;
        }
        const nonce = generateNonce();
        this._setSecurityHeaders(res, nonce);
        if (req.url === '/' || req.url === '/index.html') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            const extensionRoot = path.resolve(__dirname, '..', '..');
            res.end(renderBrowserDashboard(this._port, this._sessionToken, nonce, extensionRoot));
            return;
        }
        res.writeHead(404);
        res.end('Not Found');
    }

    /** Apply security headers to all HTTP responses. */
    private _setSecurityHeaders(res: http.ServerResponse, nonce: string): void {
        res.setHeader('Content-Security-Policy',
            "default-src 'self' blob:; " +
            `script-src 'nonce-${nonce}'; ` +
            "style-src 'self' 'unsafe-inline'; " +
            "connect-src 'self' ws://127.0.0.1:*");
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }

    /** Create the WebSocket server. */
    private async _createWebSocketServer(): Promise<void> {
        try {
            // Dynamic import to avoid hard dependency on ws
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const WebSocketModule = await import('ws').catch(() => null);
            if (!WebSocketModule) {
                return; // ws not available, server works without WebSocket
            }
            this._wsServer = new WebSocketModule.WebSocketServer({
                server: this._httpServer,
                path: '/',
                // Select 'governance-v1' subprotocol when token is present.
                // NOTE: handleProtocols does NOT reject connections — ws completes
                // the upgrade even when false is returned. Real auth is enforced
                // in the connection handler via validateWebSocketToken().
                handleProtocols: (protocols: Set<string>) => {
                    if (protocols.has(this._sessionToken)) {
                        return 'governance-v1';
                    }
                    return false;
                },
            }) as WebSocketServerLike;

            this._wsServer.on('connection', (ws: WebSocketLike, req: unknown) => {
                if (!validateWebSocketToken(req, this._sessionToken)) {
                    ws.close(4001, 'Invalid session token');
                    return;
                }
                const id = generateClientId();
                this._clients.set(id, { id, connectedAt: new Date() });
                ws.on('close', () => this._clients.delete(id));
                this._sendInitialData(ws);
            });
        } catch {
            // ws package not available - server works without WebSocket
        }
    }

    /** Send initial data snapshot to a newly connected client. */
    private async _sendInitialData(ws: WebSocketLike): Promise<void> {
        try {
            const slo = await this._sloProvider.getSnapshot();
            const topology = {
                agents: this._topologyProvider.getAgents(),
                bridges: this._topologyProvider.getBridges(),
                delegations: this._topologyProvider.getDelegations()
            };
            const audit = this._auditLogger.getRecent(50);
            ws.send(JSON.stringify({ type: 'sloUpdate', data: slo }));
            ws.send(JSON.stringify({ type: 'topologyUpdate', data: topology }));
            ws.send(JSON.stringify({ type: 'auditUpdate', data: audit }));
            if (this._policyProvider) {
                const policy = await this._policyProvider.getSnapshot();
                ws.send(JSON.stringify({ type: 'policyUpdate', data: policy }));
            }
        } catch {
            // Provider may not be ready yet; client will receive data on next broadcast cycle
        }
    }

    /** Broadcast current data to all clients. */
    private async _broadcastUpdates(): Promise<void> {
        try {
            const slo = await this._sloProvider.getSnapshot();
            this.broadcast('sloUpdate', slo);
            const topology = {
                agents: this._topologyProvider.getAgents(),
                bridges: this._topologyProvider.getBridges(),
                delegations: this._topologyProvider.getDelegations(),
            };
            this.broadcast('topologyUpdate', topology);
            this.broadcast('auditUpdate', this._auditLogger.getRecent(50));
            if (this._policyProvider) {
                const policy = await this._policyProvider.getSnapshot();
                this.broadcast('policyUpdate', policy);
            }
        } catch {
            // Non-critical: broadcast failure retries automatically on next 10s interval
        }
    }

    /** Close a server instance and run cleanup callback. */
    private _closeServer(
        server: { close(cb?: () => void): void } | undefined,
        cleanup: () => void
    ): Promise<void> {
        if (!server) { return Promise.resolve(); }
        return new Promise((resolve) => {
            server.close(() => { cleanup(); resolve(); });
        });
    }
}
