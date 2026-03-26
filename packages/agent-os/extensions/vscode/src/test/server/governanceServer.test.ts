// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Server Tests
 *
 * Unit tests for the local development server.
 */

import * as assert from 'assert';
import {
    findAvailablePort,
    isPortAvailable,
    generateClientId,
    generateSessionToken,
    checkRateLimit,
    validateWebSocketToken,
    RateLimitRecord,
    DEFAULT_HOST
} from '../../server/serverHelpers';
import { renderBrowserDashboard } from '../../server/browserTemplate';
import { GovernanceServer } from '../../server/GovernanceServer';

suite('GovernanceServer Helpers', () => {
    test('isPortAvailable returns boolean', async () => {
        const available = await isPortAvailable(49876, 'localhost');
        assert.ok(typeof available === 'boolean');
    });

    test('findAvailablePort finds port in range', async () => {
        const port = await findAvailablePort(49877, 'localhost');
        assert.ok(port >= 49877 && port < 49887);
    });

    test('generateClientId produces unique prefixed IDs', () => {
        const id1 = generateClientId();
        const id2 = generateClientId();
        assert.notStrictEqual(id1, id2);
        assert.ok(id1.startsWith('client_'));
    });

    test('generateClientId embeds timestamp', () => {
        const before = Date.now();
        const id = generateClientId();
        const timestamp = parseInt(id.split('_')[1], 10);
        assert.ok(timestamp >= before && timestamp <= Date.now());
    });
});

suite('Server Security', () => {
    test('DEFAULT_HOST binds to 127.0.0.1', () => {
        assert.strictEqual(DEFAULT_HOST, '127.0.0.1');
    });

    test('browser template includes CSP meta tag', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            html.includes('http-equiv="Content-Security-Policy"'),
            'CSP meta tag should be present in the HTML head'
        );
        assert.ok(
            html.includes("default-src 'self'"),
            'CSP should contain default-src directive'
        );
    });

    test('browser template includes SRI integrity attributes', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            html.includes('integrity="sha384-'),
            'CDN scripts should have SRI integrity attributes'
        );
        assert.ok(
            html.includes('crossorigin="anonymous"'),
            'CDN scripts should have crossorigin attribute'
        );
    });

    test('SRI hash is not a placeholder', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            !html.includes('PLACEHOLDER'),
            'SRI hash should not be a placeholder value'
        );
    });

    test('generateClientId uses crypto-strength randomness', () => {
        const id = generateClientId();
        // crypto.randomBytes(4) produces 8 hex chars
        const parts = id.split('_');
        const random = parts[2];
        assert.strictEqual(random.length, 8, 'random segment should be 8 hex chars');
        assert.ok(/^[0-9a-f]{8}$/.test(random), 'random segment should be hex');
    });
});

suite('Session Token', () => {
    test('generateSessionToken returns 32-char hex string', () => {
        const token = generateSessionToken();
        assert.strictEqual(token.length, 32, 'token should be 32 hex chars');
        assert.ok(/^[0-9a-f]{32}$/.test(token), 'token should be valid hex');
    });
    test('generateSessionToken produces unique tokens', () => {
        const t1 = generateSessionToken();
        const t2 = generateSessionToken();
        assert.notStrictEqual(t1, t2, 'tokens should be unique');
    });
    test('session token is embedded in WebSocket URL', () => {
        const token = 'abc123def456789012345678abcdef01';
        const html = renderBrowserDashboard(9845, token, 'test-nonce');
        assert.ok(
            html.includes(`?token=${token}`),
            'WebSocket URL should include session token as query parameter'
        );
    });
});

suite('Rate Limiting', () => {
    test('allows requests under the limit', () => {
        const counts = new Map<string, RateLimitRecord>();
        assert.ok(checkRateLimit('127.0.0.1', counts), 'first request should be allowed');
        assert.ok(checkRateLimit('127.0.0.1', counts), 'second request should be allowed');
    });

    test('blocks requests over 100 per minute', () => {
        const counts = new Map<string, RateLimitRecord>();
        for (let i = 0; i < 100; i++) {
            checkRateLimit('127.0.0.1', counts);
        }
        assert.ok(
            !checkRateLimit('127.0.0.1', counts),
            'request 101 should be blocked'
        );
    });

    test('resets after window expires', () => {
        const counts = new Map<string, RateLimitRecord>();
        counts.set('127.0.0.1', { count: 100, resetAt: Date.now() - 1 });
        assert.ok(
            checkRateLimit('127.0.0.1', counts),
            'should allow after window reset'
        );
    });

    test('tracks IPs independently', () => {
        const counts = new Map<string, RateLimitRecord>();
        for (let i = 0; i < 100; i++) {
            checkRateLimit('10.0.0.1', counts);
        }
        assert.ok(
            checkRateLimit('10.0.0.2', counts),
            'different IP should not be rate limited'
        );
    });
});

suite('WebSocket Token Validation', () => {
    test('accepts valid token', () => {
        const req = { url: '/?token=abc123' };
        assert.ok(validateWebSocketToken(req, 'abc123', 9845));
    });

    test('rejects invalid token', () => {
        const req = { url: '/?token=wrong' };
        assert.ok(!validateWebSocketToken(req, 'abc123', 9845));
    });

    test('rejects missing token', () => {
        const req = { url: '/' };
        assert.ok(!validateWebSocketToken(req, 'abc123', 9845));
    });

    test('rejects missing url', () => {
        assert.ok(!validateWebSocketToken({}, 'abc123', 9845));
        assert.ok(!validateWebSocketToken(null, 'abc123', 9845));
    });

    test('rejects malformed url without throwing', () => {
        const req = { url: '://bad\x00url' };
        assert.ok(!validateWebSocketToken(req, 'abc123', 9845));
    });
});

suite('CSP Nonce', () => {
    test('inline scripts include nonce attribute', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'abc123nonce');
        const nonceCount = (html.match(/nonce="abc123nonce"/g) || []).length;
        assert.ok(nonceCount >= 3, 'should have nonce on D3 + topology + client scripts');
    });

    test('CSP meta tag includes nonce directive', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'abc123nonce');
        assert.ok(
            html.includes("'nonce-abc123nonce'"),
            'CSP should include nonce directive'
        );
    });

    test('CSP includes connect-src directive', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            html.includes("connect-src 'self'"),
            'CSP should include connect-src for WebSocket'
        );
    });
});

suite('GovernanceServer Class', () => {
    const mockSlo = { getSnapshot: async () => ({}) } as any;
    const mockTopo = { getAgents: () => [], getBridges: () => [], getDelegations: () => [] } as any;
    const mockAudit = { getRecent: () => [] } as any;

    test('getInstance returns singleton', () => {
        const a = GovernanceServer.getInstance(mockSlo, mockTopo, mockAudit);
        const b = GovernanceServer.getInstance(mockSlo, mockTopo, mockAudit);
        assert.strictEqual(a, b);
    });

    test('getSessionToken is empty before start', () => {
        const server = GovernanceServer.getInstance(mockSlo, mockTopo, mockAudit);
        assert.strictEqual(server.getSessionToken(), '');
    });

    test('start generates a session token and returns a port', async () => {
        const server = GovernanceServer.getInstance(mockSlo, mockTopo, mockAudit);
        const port = await server.start(49890);
        assert.ok(port >= 49890);
        assert.ok(server.getSessionToken().length === 32);
        assert.ok(server.getUrl().includes(String(port)));
        assert.ok(server.getState().clients.length === 0);
        await server.stop();
    });
});

suite('CDN Security', () => {
    test('D3.js loaded from jsdelivr with version pin', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            html.includes('cdn.jsdelivr.net/npm/d3@7.8.5'),
            'D3.js should be loaded from jsdelivr with version pin'
        );
    });

    test('Chart.js CDN dependency removed', () => {
        const html = renderBrowserDashboard(9845, 'test-token', 'test-nonce');
        assert.ok(
            !html.includes('chart.js'),
            'Chart.js CDN script should be removed'
        );
    });
});
