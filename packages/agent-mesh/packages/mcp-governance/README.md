# AgentMesh MCP Governance Primitives

> [!IMPORTANT]
> **Public Preview** — This npm package is a Microsoft-signed public preview release.
> APIs may change before GA.

Standalone MCP governance primitives for AgentMesh. Use this package when you only need MCP authentication, signing, redaction, scanning, rate limiting, and gateway enforcement without pulling in the full SDK.

## Installation

Install the standalone MCP governance package:

```bash
npm install @microsoft/agentmesh-mcp-governance
```

If you also need AgentMesh identity, trust, policy, and audit APIs, install the full SDK instead:

```bash
npm install @microsoft/agentmesh-sdk
```

## Quick Start

```typescript
import {
  ApprovalStatus,
  CredentialRedactor,
  InMemoryMCPAuditSink,
  MCPGateway,
  MCPMessageSigner,
  MCPResponseScanner,
  MCPSecurityScanner,
  MCPSessionAuthenticator,
  MCPSlidingRateLimiter,
} from '@microsoft/agentmesh-mcp-governance';

const auditSink = new InMemoryMCPAuditSink();
const gateway = new MCPGateway({
  allowedTools: ['read_file', 'search_docs'],
  sensitiveTools: ['deploy'],
  auditSink,
  rateLimit: { maxRequests: 60, windowMs: 60_000 },
  approvalHandler: async ({ toolName }) =>
    toolName === 'deploy'
      ? ApprovalStatus.Approved
      : ApprovalStatus.Pending,
});

const decision = await gateway.evaluateToolCall('agent-1', 'read_file', {
  path: '/workspace/README.md',
});

const sessionAuth = new MCPSessionAuthenticator({
  secret: process.env.MCP_SESSION_SECRET!,
});
const signer = new MCPMessageSigner({
  secret: process.env.MCP_SIGNING_SECRET!,
});
const scanner = new MCPResponseScanner();
const metadataScanner = new MCPSecurityScanner();
const redactor = new CredentialRedactor();
const limiter = new MCPSlidingRateLimiter({ maxRequests: 10, windowMs: 1_000 });

void decision;
void sessionAuth;
void signer;
void scanner;
void metadataScanner;
void redactor;
void limiter;
```

## What You Get

- `MCPResponseScanner` — detects instruction-injection tags, imperative phrasing, credential leaks, and exfiltration URLs before tool output reaches an LLM
- `MCPSessionAuthenticator` — signs session tokens bound to agent identity with TTL expiry and concurrent-session enforcement
- `MCPMessageSigner` — HMAC-SHA256 payload signing with timestamp and nonce replay protection
- `CredentialRedactor` — removes credential material from strings and nested objects before logging or storage
- `MCPSlidingRateLimiter` — enforces per-agent sliding-window limits for MCP traffic
- `MCPSecurityScanner` — scans tool metadata for poisoning, rug pulls, cross-server collisions, description injection, and schema abuse
- `MCPGateway` — enforces deny-list, allow-list, sanitization, rate limiting, and human approval stages with fail-closed behavior

## Deployment Notes

- The in-memory stores are suitable for tests and single-process development.
- Production deployments should provide durable implementations for session, nonce, rate-limit, and audit storage.
- Audit entries are designed to carry redacted parameters only; metrics should use categorical labels rather than raw payloads.

## License

MIT — see [LICENSE](../../../../LICENSE).
