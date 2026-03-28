// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import request from 'supertest';
import { createApp } from './index';

describe('copilot extension HTTP hardening', () => {
    beforeEach(() => {
        process.env.NODE_ENV = 'test';
        process.env.VERCEL = '1';
        process.env.RATE_LIMIT_WINDOW_MS = '60000';
        process.env.RATE_LIMIT_MAX_REQUESTS = '50';
    });

    it('returns validation errors for malformed policy updates', async () => {
        const app = createApp();

        const response = await request(app)
            .post('/api/policy')
            .send({ policy: 'not-a-policy', enabled: 'yes' });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Invalid request body');
        expect(response.body.details).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ path: 'policy' })
            ])
        );
    });

    it('returns validation errors for malformed copilot requests', async () => {
        const app = createApp();

        const response = await request(app)
            .post('/api/copilot')
            .send({ messages: [] });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Invalid request body');
    });

    it('adds a trace id header to responses', async () => {
        const app = createApp();

        const response = await request(app).get('/health');

        expect(response.status).toBe(200);
        expect(response.headers['x-trace-id']).toBeTruthy();
    });

    it('rate limits repeated API requests', async () => {
        process.env.RATE_LIMIT_MAX_REQUESTS = '1';
        const app = createApp();

        const first = await request(app).get('/api/compliance');
        const second = await request(app).get('/api/compliance');

        expect(first.status).toBe(200);
        expect(second.status).toBe(429);
        expect(second.body.error).toBe('Too many requests');
    });
});