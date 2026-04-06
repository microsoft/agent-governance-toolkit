// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import express, { type Express } from 'express';
import sdk from '../../../src/index.ts';

type ToolHandler = {
  description: string;
  inputSchema: Record<string, unknown>;
  run(args: Record<string, unknown>): Promise<Record<string, unknown>>;
};

const toolHandlers: Record<string, ToolHandler> = {
  search_docs: {
    description: 'Search internal docs for a topic and return a concise answer.',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string' } },
      required: ['query'],
      additionalProperties: false,
    },
    async run(args) {
      const query = readString(args, 'query') ?? 'agent governance';
      return {
        answer: `Search results for "${query}"`,
        source: 'docs://agentmesh/owasp-mcp',
      };
    },
  },
  read_file: {
    description: 'Read a file from the demo workspace and return its contents.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        approved: { type: 'boolean' },
      },
      required: ['path'],
      additionalProperties: false,
    },
    async run(args) {
      const path = readString(args, 'path') ?? 'README.md';
      if (path.endsWith('secrets.txt')) {
        return {
          contents: 'Bearer abcdefghijklmnop demo@example.com',
          path,
        };
      }
      return {
        contents: `Read ${path} successfully.`,
        path,
      };
    },
  },
};

const toolDefinitions = Object.entries(toolHandlers).map(
  ([name, handler]) => ({
    name,
    description: handler.description,
    inputSchema: handler.inputSchema,
  }),
);

export function createExampleServer(): {
  app: Express;
  issueDemoSession(agentId?: string): Promise<string>;
} {
  const auditSink = new sdk.InMemoryMCPAuditSink();
  const redactor = new sdk.CredentialRedactor();
  const responseScanner = new sdk.MCPResponseScanner();
  const securityScanner = new sdk.MCPSecurityScanner();
  const routeRateLimiter = new sdk.MCPSlidingRateLimiter({ maxRequests: 5, windowMs: 60_000 });
  const gatewayRateLimiter = new sdk.MCPSlidingRateLimiter({ maxRequests: 5, windowMs: 60_000 });
  const sessionAuthenticator = new sdk.MCPSessionAuthenticator({
    secret: loadSecret('MCP_SESSION_SECRET'),
    ttlMs: 5 * 60_000,
  });
  const messageSigner = new sdk.MCPMessageSigner({
    secret: loadSecret('MCP_SIGNING_SECRET'),
  });
  const gateway = new sdk.MCPGateway({
    allowedTools: Object.keys(toolHandlers),
    sensitiveTools: ['read_file'],
    blockedPatterns: ['../', '..\\\\', '<system>', 'ignore previous instructions'],
    rateLimiter: gatewayRateLimiter,
    auditSink,
    approvalHandler: async ({ toolName, params }) =>
      toolName === 'read_file' && params.approved !== true
        ? sdk.ApprovalStatus.Pending
        : sdk.ApprovalStatus.Approved,
  });
  const catalogScan = securityScanner.scanServer('mcp-express-server', toolDefinitions);
  const app = express();
  app.use(express.json());

  app.get('/health', async (_request, response) => {
    response.json({
      status: 'ok',
      catalogSafe: catalogScan.safe,
      toolCount: toolDefinitions.length,
      demoAgentId: 'demo-agent',
      demoSessionToken: await issueDemoSession('demo-agent'),
    });
  });

  // Rate limiting is applied via routeRateLimiter.consume() inside the handler
  // codeql[js/missing-rate-limiting]
  app.post('/call-tool', async (request, response) => {
    const agentId = readString(request.body, 'agentId') ?? 'demo-agent';
    const toolName = readString(request.body, 'toolName') ?? '';
    const args = asRecord(request.body?.args);
    const sessionToken = request.header('x-session-token');
    const handler = toolHandlers[toolName];

    if (!sessionToken) {
      response.status(401).json({ error: 'Missing x-session-token. Call GET /health for a demo token.' });
      return;
    }
    if (!handler) {
      response.status(404).json({ error: `Unknown tool '${toolName}'` });
      return;
    }

    const session = await sessionAuthenticator.verifyToken(sessionToken, agentId);
    if (!session.valid) {
      response.status(401).json({ error: session.reason });
      return;
    }

    const signedCall = messageSigner.sign({ agentId, toolName, args });
    const signature = await messageSigner.verify(signedCall);
    if (!signature.valid) {
      response.status(401).json({ error: signature.reason });
      return;
    }

    const routeRateLimit = await routeRateLimiter.consume(`${agentId}:${toolName}`);
    if (!routeRateLimit.allowed) {
      response.status(429).json({
        error: 'Rate limit exceeded for this tool',
        rateLimit: routeRateLimit,
      });
      return;
    }

    const requestThreats = securityScanner.scanTool(
      toolName,
      `${handler.description}\nRequest payload: ${JSON.stringify(args)}`,
      handler.inputSchema,
      'mcp-express-server',
    );
    if (requestThreats.some((threat) => threat.severity === 'critical')) {
      response.status(400).json({ error: 'Security scanner rejected the request', threats: requestThreats });
      return;
    }

    const decision = await gateway.evaluateToolCall(agentId, toolName, args);
    if (!decision.allowed) {
      response.status(403).json({
        allowed: false,
        reason: decision.reason,
        findings: decision.findings,
        auditParams: decision.auditParams,
      });
      return;
    }

    const rawResult = await handler.run(args);
    const scannedResult = responseScanner.scan(rawResult);
    const safeResult = {
      safe: scannedResult.safe,
      blocked: scannedResult.blocked,
      findings: scannedResult.findings,
      sanitized: scannedResult.sanitized,
    };
    const logEntry = redactor.redact({ agentId, toolName, args, result: safeResult.sanitized }).redacted;

    if (process.env.NODE_ENV !== 'test') {
      console.info('[mcp-express-server]', JSON.stringify(logEntry));
    }

    response.status(scannedResult.blocked ? 422 : 200).json({
      allowed: true,
      reason: decision.reason,
      messageVerification: signature,
      response: safeResult,
      auditEntries: auditSink.getEntries().length,
    });
  });

  async function issueDemoSession(agentId: string = 'demo-agent'): Promise<string> {
    const issued = await sessionAuthenticator.issueToken(agentId);
    return issued.token;
  }

  return { app, issueDemoSession };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function readString(value: unknown, key: string): string | undefined {
  const record = asRecord(value);
  return typeof record[key] === 'string' ? record[key] as string : undefined;
}

function loadSecret(envName: string): string {
  const secret = process.env[envName];
  if (secret && Buffer.byteLength(secret, 'utf-8') >= 32) {
    return secret;
  }
  return randomBytes(32).toString('hex');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 3000);
  const { app } = createExampleServer();
  app.listen(port, () => {
    console.log(`MCP Express example listening on http://127.0.0.1:${port}`);
  });
}
