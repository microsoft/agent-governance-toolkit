// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

let app: any;
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  process.env.VERCEL = '1';
  delete process.env.ALLOWED_ORIGINS;

  const mod = await import('../index');
  app = mod.app;

  server = app.listen(0);
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe('CORS allowlist middleware', () => {
  test('allows request from default GitHub origin', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'https://github.com' },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('https://github.com');
  });

  test('rejects disallowed origin', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'https://evil.example.com' },
    });

    expect(response.status).toBe(403);
  });

  test('rejects github-like malicious subdomain', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'https://github.com.evil.com' },
    });

    expect(response.status).toBe(403);
  });

  test('allows trailing slash origin after normalization', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'https://github.com/' },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('https://github.com');
  });

  test('rejects non-standard port when not allowlisted', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'https://github.com:8080' },
    });

    expect(response.status).toBe(403);
  });

  test('rejects malformed origin header', async () => {
    const response = await fetch(`${baseUrl}/api/status`, {
      headers: { Origin: 'http://' },
    });

    expect(response.status).toBe(403);
  });

  test('rejects missing origin on protected API route', async () => {
    const response = await fetch(`${baseUrl}/api/status`);
    expect(response.status).toBe(403);
  });

  test('allows missing origin on excluded health route', async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.status).toBe(200);
  });

  test('rejects preflight from disallowed origin', async () => {
    const response = await fetch(`${baseUrl}/api/copilot`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.example.com',
        'Access-Control-Request-Method': 'POST',
      },
    });

    expect(response.status).toBe(403);
  });

  test('allows preflight from allowed origin', async () => {
    const response = await fetch(`${baseUrl}/api/copilot`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://github.com',
        'Access-Control-Request-Method': 'POST',
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-origin')).toBe('https://github.com');
  });
});
