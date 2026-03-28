import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as http from 'http';

// Set VERCEL=1 to prevent the app from automatically calling listen(3000) on import
process.env.VERCEL = '1';
import { app } from '../index';

describe('Express API Payload Limits (DoS Prevention)', () => {
    let server: http.Server;
    let port: number;

    beforeAll((done) => {
        // Find an available port dynamically
        server = app.listen(0, () => {
            const address = server.address();
            port = typeof address === 'string' ? 0 : address?.port || 0;
            done();
        });
    });

    afterAll((done) => {
        if (server) {
            server.close(done);
        }
    });

    // Helper function to make HTTP POST requests without external dependencies like supertest or assume fetch is fully supported
    const makePostRequest = (endpoint: string, payload: string): Promise<http.IncomingMessage> => {
        return new Promise((resolve, reject) => {
            const req = http.request({
                hostname: 'localhost',
                port: port,
                path: endpoint,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload)
                }
            }, (res) => {
                res.on('data', () => { }); // Consume data stream
                res.on('end', () => resolve(res));
            });
            req.on('error', reject);
            req.write(payload);
            req.end();
        });
    };

    it('should reject requests with payloads larger than 1MB (413 Payload Too Large)', async () => {
        // Create a payload larger than 1MB (1.5MB)
        const largePayload = JSON.stringify({ data: 'a'.repeat(1.5 * 1024 * 1024) });

        const res = await makePostRequest('/api/webhook', largePayload);

        expect(res.statusCode).toBe(413);
    });

    it('should accept requests with payloads smaller than 1MB', async () => {
        // Create a payload well under 1MB (100KB)
        const smallPayload = JSON.stringify({ data: 'a'.repeat(100 * 1024) });

        const res = await makePostRequest('/api/webhook', smallPayload);

        // Since we aren't providing an x-hub-signature for webhook, we may get a 401 Unauthorized or 200,
        // but it should NOT be 413 Payload Too Large.
        expect(res.statusCode).not.toBe(413);
    });

    it('should reject requests with payloads slightly over 1MB edge case', async () => {
        // String is exactly 1MB, but JSON formatting adds ~12 bytes pushing it over the exact 1048576 limit
        const exactPayload = JSON.stringify({ data: 'a'.repeat(1024 * 1024) });
        const res = await makePostRequest('/api/webhook', exactPayload);
        expect(res.statusCode).toBe(413);
    });

    it('should accept requests with payloads just under 1MB edge case', async () => {
        // Removing 20 bytes guarantees the final JSON string is under the rigid bytes limit
        const underLimitPayload = JSON.stringify({ data: 'a'.repeat(1024 * 1024 - 20) });
        const res = await makePostRequest('/api/webhook', underLimitPayload);
        expect(res.statusCode).not.toBe(413);
    });
});
