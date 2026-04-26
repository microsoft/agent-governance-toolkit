# Security Model: Agent OS VS Code Extension

This document describes the security architecture of the Agent OS VS Code extension. It covers three security domains: the Governance Server (browser dashboard), the REST client (live data), and the subprocess lifecycle (agent-failsafe server management).

For vulnerability reporting, see the [repository-level SECURITY.md](../../../../SECURITY.md).

## Threat Model

The extension operates in three security contexts:

1. **Governance Server** — local HTTP/WebSocket server for the browser dashboard. Binds to `127.0.0.1` only.
2. **REST Client** — polls a local agent-failsafe REST server for live governance data. Connects to loopback only.
3. **Subprocess Manager** — spawns and manages the agent-failsafe server process. Runs `pip install` when the package is missing.

**In scope:** Other local processes, malicious browser tabs, cross-origin attacks, compromised REST servers, malicious `.vscode/settings.json` in cloned repositories, supply chain risks from pip install.

**Out of scope:** Remote network attacks (all bindings are loopback), physical access, compromised VS Code host process.

### Attack Vectors Addressed

| Vector | Mitigation | Source |
|--------|-----------|--------|
| Cross-origin WebSocket hijacking | Session token on WS upgrade | `GovernanceServer.ts:197-198` |
| Script tampering | Local vendor bundling (no CDN) | `assets/vendor/d3.v7.8.5.min.js`, `assets/vendor/chart.v4.4.1.umd.min.js` |
| XSS via dashboard content | CSP nonces + shared `escapeHtml` utility | `GovernanceServer.ts:176`, `utils/escapeHtml.ts` |
| Local DoS via request flooding | Rate limiting (100 req/min) | `serverHelpers.ts:99-112` |
| REST response memory exhaustion | 5MB cap + array size limits | `liveClient.ts:89`, `translators.ts:19-22` |
| Token exfiltration via redirect | `maxRedirects: 0` | `liveClient.ts:91` |
| Non-loopback endpoint in settings | `isLoopbackEndpoint()` validation | `liveClient.ts:60-63` |
| Malicious pip package name | Hardcoded `agent-failsafe[server]` | `sreServer.ts:71` |

## Security Controls

### 1. Loopback-Only Binding

The Governance Server binds to `127.0.0.1`. The REST client validates endpoints against a loopback allowlist. Neither is configurable to bind remotely.

**Why loopback, not `0.0.0.0` with authentication:** The session token is transmitted over plaintext HTTP. On a non-loopback interface, any device on the same network could intercept it via packet capture. Authentication alone cannot compensate for plaintext transport on a shared network. Binding to loopback eliminates the entire class of network-adjacent attacks.

```
Server binding: serverHelpers.ts:14 — DEFAULT_HOST = '127.0.0.1'
Client validation: liveClient.ts:48 — LOOPBACK_HOSTS = Set(['127.0.0.1', 'localhost', '::1', '[::1]'])
Client enforcement: liveClient.ts:60-63 — isLoopbackEndpoint() parses URL, checks hostname
Constructor guard: liveClient.ts:81 — throws if endpoint is not loopback
Factory guard: providerFactory.ts:67 — explicit endpoint checked before use
```

### 2. Session Token Authentication

Each server start generates a 32-character hex token using `crypto.randomBytes(16)`. The token is embedded in the dashboard HTML and required on WebSocket upgrade.

**Why this exists:** Without session tokens, any local process that discovers the port can open a WebSocket and receive governance data. The token acts as a capability: only the browser tab that received the HTML can authenticate.

**Limitation:** The token is in the HTML response over plaintext HTTP. A process with loopback traffic access could intercept it. This is accepted for a localhost dev server — TLS would require certificate management with no meaningful security gain on loopback.

```
Generation: serverHelpers.ts:73-74 — randomBytes(16).toString('hex')
Assignment: GovernanceServer.ts:81 — this._sessionToken = generateSessionToken()
Validation: GovernanceServer.ts:197-198 — validateWebSocketToken + close(4001)
Embedding: browserScripts.ts:25 — token in WebSocket URL
```

### 3. Rate Limiting

HTTP requests are limited to 100 per minute per client IP. Excess requests receive HTTP 429 with `Retry-After: 60`. State is cleared on `stop()`.

**Why 100/min:** Normal dashboard polling is 6 req/min (every 10s). The cap provides headroom for page loads and reconnections while blocking flood attacks.

```
Implementation: serverHelpers.ts:99-112 — checkRateLimit()
Enforcement: GovernanceServer.ts:156-157 — 429 response
Cleanup: GovernanceServer.ts:94 — requestCounts.clear() on stop
```

### 4. Content Security Policy (CSP)

Both the HTTP header and HTML meta tag enforce a restrictive CSP with per-request nonces:

```
default-src 'self';
script-src 'nonce-{random}';
style-src 'self' 'unsafe-inline';
connect-src 'self'
```

**Why nonces instead of `'unsafe-inline'`:** Nonces allow only server-rendered scripts to execute. An XSS injection that adds a `<script>` tag cannot guess the nonce, so the injected script is blocked.

**Why `'unsafe-inline'` for styles only:** The dashboard embeds CSS in a `<style>` block. Style injection is lower risk than script injection — it can leak data via CSS selectors but cannot execute arbitrary code.

**Why `connect-src 'self'`:** Explicitly governs WebSocket connections. Without it, `default-src 'self'` would apply, which works but relies on implicit fallback behavior that varies across browsers.

```
HTTP header: GovernanceServer.ts:174-178 — setHeader with nonce
Meta tag: browserTemplate.ts:119-120 — content attribute with nonce
Script nonces: browserTemplate.ts:122,130-131 — nonce on all 3 script tags
Nonce generation: GovernanceServer.ts:161 — generateNonce() per request
```

### 5. Local Asset Bundling

D3.js v7.8.5 and Chart.js v4.4.1 are vendored locally under `assets/vendor/`. No external CDN is referenced at runtime. Scripts are inlined into HTML templates via `fs.readFileSync` and protected by CSP nonces.

```
Source: assets/vendor/d3.v7.8.5.min.js (vendored, 280KB)
Source: assets/vendor/chart.v4.4.1.umd.min.js (vendored, 205KB)
Usage: browserTemplate.ts — inlined into <script nonce="..."> tag
```

### 6. XSS Prevention

User-controlled strings in the audit log are escaped via a `textContent`-based sanitizer:

```javascript
function esc(s) {
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}
```

**Why `textContent`/`innerHTML` instead of regex or DOMPurify:** Setting `textContent` causes the browser's own parser to entity-encode all HTML metacharacters (`<`, `>`, `&`, `"`). Reading back via `innerHTML` retrieves the encoded string. This is safer than regex escaping because the browser handles all edge cases. DOMPurify would add an external dependency (violating zero-new-deps policy) and is designed for sanitizing untrusted HTML, not encoding plain text.

Staleness indicators use `textContent` exclusively — never `innerHTML`. Only computed integers and literal strings reach the DOM.

```
esc() function: browserScripts.ts:13-15
esc() usage: browserScripts.ts:82-83 — all audit entry fields pass through esc()
Staleness (textContent): browserScripts.ts:46-49, GovernanceHubScript.ts:83, SLODashboardScript.ts:186
```

### 7. REST Client Input Validation

The extension polls agent-failsafe's REST endpoints for live data. All responses are validated before use.

**Response size cap (5MB):** Typical governance snapshots are under 100KB. The 5MB cap provides headroom for fleet arrays approaching the 1000-agent cap while preventing memory exhaustion from a compromised server. JSON parsing is the attack surface — a multi-gigabyte response would exhaust the extension host's heap before translator array caps could apply.

**Redirect prevention (`maxRedirects: 0`):** A compromised loopback server could return a 3xx redirect to an external host. If followed, the `Authorization: Bearer` header would be forwarded to the attacker's server. Zero redirects eliminates this vector.

**Error sanitization:** `_sanitizeError()` returns only fixed-set messages: Connection refused, Request timeout, Network error, Server error, Connection failed. Raw response bodies, URLs, and headers are never exposed in the cache or UI.

**Token storage:** Bearer token stored in VS Code SecretStorage, never in `settings.json`. **Why SecretStorage:** `settings.json` is plaintext, often version-controlled, and readable by any VS Code extension. SecretStorage uses the OS credential store (Keychain on macOS, Credential Vault on Windows, libsecret on Linux), encrypting the token at rest and isolating it from other extensions.

```
Size cap: liveClient.ts:45,89-90 — MAX_RESPONSE_BYTES = 5MB, maxContentLength + maxBodyLength
Redirect block: liveClient.ts:91 — maxRedirects: 0
Error sanitization: liveClient.ts:191-199 — _sanitizeError returns fixed set
Token header: liveClient.ts:93 — Authorization: Bearer
Array caps: translators.ts:19-22 — 1000 agents, 500 events, 200 policies
String truncation: translators.ts:22,36 — 500 chars default
Rate clamping: translators.ts:41-45 — rejects values outside [0,1], Infinity, NaN
Date validation: translators.ts:47-52 — safeDate() rejects invalid strings
```

### 8. Subprocess Security

The extension spawns `python -m agent_failsafe.rest_server` as a managed child process.

**Hardcoded package name:** The pip install command uses the literal string `agent-failsafe[server]` — not user input. This prevents command injection via settings.

**Python path from settings:** The `agentOS.governance.pythonPath` setting controls which Python interpreter is used. A malicious `.vscode/settings.json` could point this to a non-Python binary. The `isAgentFailsafeAvailable` check runs `python -c "import agent_failsafe.rest_server"` — if the binary is not Python or agent-failsafe is not installed, the import fails and the extension falls back to disconnected mode.

**No shell execution:** All `spawn()` calls use argument arrays, never `shell: true`. This prevents shell injection via crafted Python paths.

**Process lifecycle:** The child process is spawned with `detached: false` and killed on extension deactivation via `dispose()`. No orphan processes.

```
Availability check: sreServer.ts:37-44 — spawn with -c import check
Pip install: sreServer.ts:71 — hardcoded 'agent-failsafe[server]'
Server spawn: sreServer.ts:120-124 — argument array, no shell
Process kill: sreServer.ts:146-149 — stop() kills child
Detached false: sreServer.ts:123 — detached: false
```

## Accepted Risks

| Risk | Severity | Rationale |
|------|----------|-----------|
| Session token over plaintext HTTP | Low | Loopback only. See Section 1. |
| Rate limiter Map grows during session | Low | Entries expire (1-min windows). Map cleared on `stop()`. Only loopback IPs. |
| No timing-safe token comparison | Low | Exploitation requires loopback access + sub-microsecond measurement. |
| REST data over plaintext HTTP | Low | Same as session token. Data is metrics, not credentials. |
| asiCoverage inner entries not validated | Low | Outer object check applied. Consumers access via optional chaining. |
| Python path from user settings | Low | Non-Python binary fails the import check. No shell execution. |
| pip install runs with user privileges | Low | Standard pip behavior. Extension prompts before installing. |

## Test Coverage

| Suite | Tests | What It Verifies |
|-------|-------|------------------|
| Server Security | 5 | CSP, local vendor, no placeholders, crypto randomness, loopback binding |
| Session Token | 3 | Format (32 hex), uniqueness, embedding in WS URL |
| Rate Limiting | 4 | Allow under limit, block at 101, window reset, per-IP isolation |
| WebSocket Token Validation | 5 | Valid, invalid, missing, missing URL, malformed URL |
| CSP Nonce | 3 | Nonce on scripts, nonce in CSP, connect-src |
| Vendor Assets | 3 | D3 exists + size, Chart.js exists + size, no CDN in source |
| isLoopbackEndpoint | 8 | Loopback accepted, external/empty/javascript: rejected |
| LiveSREClient | 5 | Non-loopback rejected, initial state, interval clamp, dispose |
| translateSLO | 10 | Mapping, boundaries, snake_case, rejection, no fabrication |
| translateTopology | 11 | Fleet mapping, caps, truncation, optional fields, snake_case |
| translatePolicy | 8 | Policy mapping, caps, ASI coverage, empty handling |
| providerFactory | 4 | Not-installed state, no fake data, dispose, endpoint override |

## Claim-to-Source Map

| Claim | Status | Source |
|-------|--------|--------|
| Server binds to 127.0.0.1 only | implemented | `serverHelpers.ts:14` |
| Session token uses crypto.randomBytes(16) | implemented | `serverHelpers.ts:73-74` |
| Token required for WebSocket connection | implemented | `GovernanceServer.ts:197-198` |
| Invalid token returns close code 4001 | implemented | `GovernanceServer.ts:198` |
| Rate limit: 100 req/min per IP | implemented | `serverHelpers.ts:105` |
| Rate limit returns 429 with Retry-After | implemented | `GovernanceServer.ts:157` |
| Rate limit state cleared on stop | implemented | `GovernanceServer.ts:94` |
| CSP with per-request nonces | implemented | `GovernanceServer.ts:174-178` |
| CSP connect-src for WebSocket | implemented | `GovernanceServer.ts:178` |
| Nonce on all inline script tags | implemented | `browserTemplate.ts:122,130-131` |
| D3.js vendored locally (no CDN) | implemented | `assets/vendor/d3.v7.8.5.min.js` |
| XSS escaping via escapeHtml | implemented | `utils/escapeHtml.ts`, inline `esc()` in browser scripts |
| Staleness display uses textContent only | implemented | `browserScripts.ts:46-49` |
| Loopback endpoint validation | implemented | `liveClient.ts:60-63` |
| Constructor rejects non-loopback | implemented | `liveClient.ts:81` |
| maxContentLength 5MB | implemented | `liveClient.ts:89-90` |
| maxRedirects 0 | implemented | `liveClient.ts:91` |
| Token via Authorization Bearer header | implemented | `liveClient.ts:93` |
| Error messages sanitized to fixed set | implemented | `liveClient.ts:191-199` |
| Fleet agents capped at 1000 | implemented | `translators.ts:19` |
| Audit events capped at 500 | implemented | `translators.ts:20` |
| Policies capped at 200 | implemented | `translators.ts:21` |
| Strings truncated at 500 chars | implemented | `translators.ts:22,36` |
| Pip install uses hardcoded package name | implemented | `sreServer.ts:71` |
| No shell: true in any spawn call | implemented | `sreServer.ts:39-40,120-124` |
| Server process killed on dispose | implemented | `sreServer.ts:146-149` |
| Auto-install prompts user first | implemented | `sreServer.ts:55-60` |
| Configurable rate limit threshold | planned | Hardcoded at 100 |
| TLS support for local server | deferred | Accepted risk for loopback-only |
