# Security Model: Agent OS VS Code Extension

This document describes the security architecture of the Agent OS VS Code extension's Governance Server, the local HTTP/WebSocket server that serves the browser-based governance dashboard.

For vulnerability reporting, see the [repository-level SECURITY.md](../../../../SECURITY.md).

## Threat Model

The Governance Server is a local development tool. It binds to `127.0.0.1` and serves governance dashboard data over HTTP and WebSocket to the developer's browser.

**In scope:** Protect against other local processes, malicious browser tabs, and cross-origin attacks that attempt to read governance data or inject commands via the dashboard's WebSocket connection.

**Out of scope:** Remote network attacks (server never binds to `0.0.0.0`), physical access, compromised VS Code host process.

### Attack Vectors Addressed

| Vector | Mitigation | Source |
|--------|-----------|--------|
| Cross-origin WebSocket hijacking | Session token authentication on WebSocket upgrade | `GovernanceServer.ts:193-196` |
| CDN script tampering | Subresource Integrity (SRI) hashes on all CDN scripts | `browserTemplate.ts:95` |
| XSS via injected dashboard content | Content Security Policy restricts script sources | `GovernanceServer.ts:171-176` |
| Local DoS via request flooding | Rate limiting (100 requests/minute per IP) | `serverHelpers.ts:85-101` |
| Cross-site data exfiltration | `X-Content-Type-Options: nosniff` header | `GovernanceServer.ts:177` |

## Security Controls

### 1. Loopback-Only Binding

The server binds exclusively to `127.0.0.1`. This is not configurable. Remote connections are structurally impossible.

```
Source: serverHelpers.ts:14
DEFAULT_HOST = '127.0.0.1'
```

### 2. Session Token Authentication

Each server start generates a cryptographically random 32-character hex token using Node.js `crypto.randomBytes(16)`. The token is embedded in the dashboard HTML and required as a query parameter on WebSocket upgrade requests.

```
Flow:
  start() -> generateSessionToken() -> 32-char hex
  renderBrowserDashboard(port, token) -> HTML embeds token in WS URL
  ws://localhost:{port}?token={token} -> validated on connection
  Invalid/missing token -> close(4001, 'Invalid session token')
```

**Why this exists:** Without session tokens, any local process or browser tab that knows the port number can open a WebSocket connection and receive governance data. The token acts as a capability: only the browser tab that received the dashboard HTML can authenticate.

**Limitation:** The token is embedded in the HTML response served over plaintext HTTP. A process with access to loopback traffic could intercept it. This is an accepted trade-off for a localhost development server — TLS would require certificate management that adds friction without meaningful security gain in the loopback context.

```
Source: serverHelpers.ts:73-75 (generation)
Source: GovernanceServer.ts:80 (assignment)
Source: GovernanceServer.ts:193-196 (validation)
Source: browserScripts.ts:24 (embedding)
```

### 3. Rate Limiting

HTTP requests are rate-limited to 100 per minute per client IP using a sliding window counter. Requests exceeding the limit receive HTTP 429 with a `Retry-After: 60` header.

Rate limit state is stored in a `Map<string, RateLimitRecord>` and cleared on server stop to prevent stale data across restarts.

**Why this exists:** Prevents a runaway script or browser bug from overwhelming the server. The limit (100/min) accommodates normal dashboard polling (every 10 seconds = 6/min) with headroom for page loads and reconnections.

**Design choice:** The rate limiter uses a fixed window rather than a sliding window or token bucket. This is simpler and sufficient for a localhost dev server where precision is less important than reliability.

```
Source: serverHelpers.ts:90-101 (checkRateLimit)
Source: GovernanceServer.ts:154-158 (enforcement)
Source: GovernanceServer.ts:93 (cleanup on stop)
```

### 4. Content Security Policy (CSP)

Both the HTTP response header and the HTML `<meta>` tag enforce a restrictive CSP with per-request nonces:

```
default-src 'self';
script-src 'nonce-{random}' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline';
connect-src 'self'
```

A fresh cryptographic nonce is generated for each HTTP request. All inline `<script>` tags and the CDN `<script>` tag carry `nonce="{random}"` attributes. Scripts without the matching nonce are blocked.

`'unsafe-inline'` is permitted for styles only because the dashboard embeds CSS directly in the HTML document. The `connect-src 'self'` directive explicitly governs WebSocket connections.

```
Source: GovernanceServer.ts:163-169 (HTTP header with nonce)
Source: browserTemplate.ts:105-106 (meta tag with nonce)
Source: browserTemplate.ts:119-121 (nonce on script tags)
```

### 5. Subresource Integrity (SRI)

External CDN scripts include SRI hashes to detect tampering:

| Library | Version | CDN | SRI Hash |
|---------|---------|-----|----------|
| D3.js | 7.8.5 | cdn.jsdelivr.net | `sha384-su5kReKyYlIFrI62mbQRKXHzFobMa7BHp1cK6julLPbnYcCW9NIZKJiTODjLPeDh` |

Chart.js was removed in v1.1.0 (unused dependency). D3.js was moved from `d3js.org` to `cdn.jsdelivr.net` with a pinned version (`d3@7.8.5`) for SRI compatibility.

If the CDN serves a modified file, the browser will refuse to execute it.

```
Source: browserTemplate.ts:95 (D3_SRI constant)
Source: browserTemplate.ts:112-114 (script tag)
```

### 6. XSS Prevention

User-controlled strings displayed in the audit log are escaped via a `textContent`-based sanitizer:

```javascript
function esc(s) {
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}
```

All audit entry fields (`type`, `time`, `reason`, `violation`) pass through `esc()` before insertion into the DOM.

```
Source: browserScripts.ts:13-17 (esc function)
Source: browserScripts.ts:69-71 (usage in buildAuditItem)
```

## Accepted Risks

| Risk | Severity | Rationale |
|------|----------|-----------|
| Session token transmitted over plaintext HTTP | Low | Server binds to loopback only. TLS would require local certificate management with no meaningful security gain. |
| Rate limiter Map grows unbounded during server lifetime | Low | Map entries expire naturally (1-minute windows). Server is short-lived (development sessions). Map is cleared on `stop()`. |
| No timing-safe token comparison | Low | `===` comparison on session tokens is theoretically vulnerable to timing attacks. In practice, the attacker would need loopback network access and the ability to measure sub-microsecond timing differences, which is not realistic for a localhost dev tool. |

## Test Coverage

Security controls are tested in `src/test/server/governanceServer.test.ts`:

| Suite | Tests | What It Verifies |
|-------|-------|------------------|
| Server Security | 5 | CSP presence, SRI attributes, no placeholders, crypto randomness, loopback binding |
| Session Token | 3 | Token format (32 hex chars), uniqueness, embedding in WebSocket URL |
| Rate Limiting | 4 | Allow under limit, block at 101, window reset, per-IP isolation |
| WebSocket Token Validation | 4 | Valid token, invalid token, missing token, missing URL |
| CSP Nonce | 3 | Nonce on script tags, nonce in CSP directive, connect-src present |
| CDN Security | 2 | D3.js version pin, Chart.js removal |

## Claim-to-Source Map

| Claim | Status | Source |
|-------|--------|--------|
| Server binds to 127.0.0.1 only | implemented | `serverHelpers.ts:14` |
| Session token uses crypto.randomBytes(16) | implemented | `serverHelpers.ts:74` |
| Token required for WebSocket connection | implemented | `GovernanceServer.ts:193-196` |
| Invalid token returns close code 4001 | implemented | `GovernanceServer.ts:195` |
| Rate limit: 100 req/min per IP | implemented | `serverHelpers.ts:95-96` |
| Rate limit returns 429 with Retry-After | implemented | `GovernanceServer.ts:155-157` |
| Rate limit state cleared on stop | implemented | `GovernanceServer.ts:93` |
| CSP with per-request nonces | implemented | `GovernanceServer.ts:163-169` |
| CSP connect-src for WebSocket | implemented | `GovernanceServer.ts:168` |
| Nonce on all inline script tags | implemented | `browserTemplate.ts:119-121` |
| D3.js SRI hash verified | implemented | `browserTemplate.ts:95` |
| Chart.js CDN removed | implemented | `browserTemplate.ts:100-115` |
| XSS escaping on audit entries | implemented | `browserScripts.ts:13-17` |
| 21 security-related tests | implemented | `governanceServer.test.ts:60-232` |
| Configurable rate limit threshold | planned | Not yet implemented; hardcoded at 100 |
| TLS support for local server | deferred | Accepted risk for loopback-only server |
