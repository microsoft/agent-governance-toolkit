# Changelog

All notable changes to AgentMesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **HTTP trust middleware request authentication.** `TrustMiddleware` no longer
  accepts a caller-supplied `X-Agent-DID` header as proof of identity. It
  previously started from a trust score of `1.0` and only lowered it inside an
  `except` branch that could never execute, so any caller who set the header was
  verified with full trust and `X-Agent-Capabilities` was honoured as
  self-asserted authorization. Callers now prove possession of a registered
  Ed25519 key over a canonical envelope binding DID, audience, timestamp, nonce,
  method, undecoded request target, target mode, covered request headers, and
  body digest, with single-use nonce replay protection. Verification keys and
  capabilities are resolved only from a
  trusted registry, never from request headers. The Flask, FastAPI, and Django
  integrations now share one envelope implementation, and the header lookup is
  case-insensitive so the FastAPI path no longer silently misses the trust
  headers Starlette lowercases. See `BREAKING_CHANGES.md` — clients must be
  upgraded alongside servers.
- **The signed target is the undecoded one.** Signing the percent-decoded path
  made `/files/a%2Fb` and `/files/a/b` produce identical signed bytes, so a
  signature captured for one was valid for the other wherever a proxy, gateway,
  or audit log reads the target before the application decodes it. All three
  integrations now sign the raw origin-form target from `RAW_URI`,
  `REQUEST_URI`, or `scope["raw_path"]`, and servers that publish none of these
  fail with `500` rather than silently downgrading. `target_mode` travels inside
  the signed bytes, so a raw↔decoded downgrade fails closed.
- **Covered headers are chosen by the server and bind presence.** `Content-Type`
  was signed as `""` when absent, so an attacker could add one the signer never
  sent — enough to change how a body is parsed. Headers named by
  `TrustConfig.signed_header_names` are now omitted from the envelope when
  absent, so adding or stripping one invalidates the signature. The covered set
  is server-configured rather than caller-declared, so a caller cannot narrow
  its own coverage.
- **Verification is time-bounded.** `TrustConfig.io_timeout_seconds` (default
  `5.0`) budgets an entire verification rather than each dependency call, so a
  slow peer resolver cannot hand its remaining time to a slow replay cache. The
  remaining budget is passed to resolvers and caches that declare a
  `timeout_seconds` parameter, the budget is re-checked before the nonce is
  consumed so a doomed request never burns a single-use nonce, and exhaustion
  denies with `503`.
- **Django exempt routes no longer publish an unverified DID.** `@trust_exempt`
  views and exempt path prefixes copied the attacker-controlled `X-Agent-DID`
  header onto `request.agent_did`, so a view that logged or authorized on it
  received a value nothing had verified. Exempt and denied requests now set
  `agent_did=None`, `agent_trust_score=None`, and `agent_authenticated=False`.
- **`@trust_required(min_score=0)` still requires authentication.** The Django
  gate compared only the trust score, so a zero floor admitted a caller whose
  signature had failed — a deliberately open route silently became an
  unauthenticated one. Authentication is now checked before the score.
- **Anonymous callers cannot reach protected routes.** `flask_trust_required`
  and `fastapi_trust_required` reject any result that is not cryptographically
  authenticated, so a `permissive_mode` deployment no longer admits an
  unauthenticated caller to a route that requires capabilities. Serving
  anonymous callers now requires the explicitly-named `flask_trust_optional` /
  `fastapi_trust_optional` variants, and `TrustConfig` refuses to combine
  `permissive_mode` with an authorization gate.
- **Unauthenticated request-handling hardening.** The signed body is read
  against `max_signed_body_bytes` before buffering, so an unauthenticated caller
  cannot force unbounded memory allocation; `install_fastapi_trust` installs the
  pre-routing body guard and returns a dependency bound to it, and that
  dependency now fails closed with `500` when the guard is absent rather than
  verifying a body FastAPI has already buffered without limit; a presented
  public key is compared as
  decoded bytes rather than base64 text, so a non-ASCII header value can no
  longer raise inside the auth path; `401` responses no longer disclose which
  DIDs are registered; DIDs are bounded and charset-checked before reaching a
  resolver or a log sink; replay-cache exhaustion is reported as `503` rather
  than being recorded as a replay attempt; and replay keys are namespaced by
  audience so services sharing a cache cannot burn each other's nonces.
- **Server faults are no longer reported as authentication failures.** A peer
  resolver that raises, an unreadable request body, and any unexpected internal
  error now return `503` instead of `401`, so an identity-store outage cannot
  masquerade as every caller presenting bad credentials and stays visible to
  alerting keyed on server errors. `TrustConfig` is frozen so the
  `permissive_mode` guard cannot be voided by post-construction assignment, and
  it rejects a bare string for `required_capabilities`, which was previously
  expanded character-by-character into an unsatisfiable authorization gate.
- **Denial telemetry and decorator hardening.** Pre-authentication failures stay
  at `DEBUG` so they cannot be used to flood logs, but each distinct denial
  reason now also emits a rate-limited `WARNING` carrying a coarse reason and
  status — never the DID — so an attack is visible at default log levels. The
  Flask and FastAPI decorators extend `verify_request`'s never-raise guarantee
  over the body read that precedes it, and both derive the signed request target
  from the raw query bytes, so a client disconnect or a non-UTF-8 query no longer
  produces a `500` and both frameworks sign identical payloads. Internal-fault
  tracebacks are emitted at most once per minute per call site, so a failing peer
  resolver cannot amplify one fault into an `ERROR` traceback per request, and a
  missing-capability denial is now logged with the agent's DID so privilege
  probing by an authenticated agent is visible.
- **AgentMesh transport message authentication.** `MeshClient` no longer lets a
  sender-supplied `plaintext` wire flag select the legacy no-crypto receive path;
  whether an inbound message is treated as plaintext is decided solely by the
  receiver's own `plaintextPeers` configuration. Once a peer has been end-to-end
  verified it can never be handled as plaintext again — the check latches on the
  E2E-verified set rather than on a live session, so tearing the session down
  (ratchet desync or an unauthenticated `knock_reject`) cannot re-open the
  plaintext path. An encrypted frame that is missing its ratchet header is now
  dropped before the pre-KNOCK buffer instead of being buffered until TTL
  eviction.
- **Relay sender-identity binding.** The relay binds the frame `from` field to the
  connection's cryptographically verified DID identity for message and knock
  frames (including `knock_accept` / `knock_reject`, and on the offline store
  path), so a connected peer can no longer emit frames under another agent's DID.
- **Relay acknowledgement ownership.** `InboxStore.acknowledge` enforces recipient
  ownership (spec §12.3): a peer may only acknowledge and delete messages addressed
  to its own verified DID, preventing one agent from deleting another's queued mail.

### Fixed

- **Pending-message batch isolation.** A single malformed entry in a relay-supplied
  `pending_messages` batch no longer aborts the drain; the failure is surfaced
  through the error handler and the remaining queued messages are still delivered.

### Changed

- **Displaced connections now close with a distinct WebSocket code.** When a second
  connection authenticates for a DID, the relay closes the displaced socket with
  `4006` (`WS_CLOSE_SESSION_REPLACED`) instead of `1000`. `1000` was reported by
  `MeshClient` as a client-initiated close, making an involuntary takeover
  indistinguishable from the agent calling `disconnect()` on itself — so a
  displaced agent could neither detect nor report it. The new code is reported as
  a server close and raised through `onError`, while still suppressing
  auto-reconnect so the displaced and replacing sockets do not evict each other in
  a loop. Hosts that previously matched on close code `1000` to detect replacement
  should match `WS_CLOSE_SESSION_REPLACED` (exported from `mesh-client`) instead.

## [1.0.0-alpha.1] - 2026-02-01

### Added

#### Layer 1: Identity & Zero-Trust Core
- `AgentIdentity` - First-class agent identity with Ed25519 cryptographic keys
- `AgentDID` - Decentralized identifiers for agents
- `ScopeChain` - Scope chains for scope narrowing
- `HumanSponsor` - Human sponsor accountability for every agent
- `Credential` - Ephemeral credentials with 15-minute default TTL
- `CredentialManager` - Automatic credential rotation and revocation
- `RiskScorer` - Continuous risk scoring updated every 30 seconds
- `SPIFFEIdentity` - SPIFFE/SVID workload identity for mTLS

#### Layer 2: Trust & Protocol Bridge
- `TrustBridge` - Unified trust layer across A2A, MCP, IATP, ACP
- `A2AAdapter` - Google A2A protocol support (Agent Card, task lifecycle)
- `MCPAdapter` - Anthropic MCP protocol support (tool registration, resource binding)
- `TrustHandshake` - IATP trust handshakes with <200ms target
- `CapabilityScope` - Capability-scoped credential issuance
- `CapabilityRegistry` - Resource and action-level capability control

#### Layer 3: Governance & Compliance Plane
- `PolicyEngine` - Declarative policy engine (YAML/JSON) with <5ms evaluation
- `Policy` and `PolicyRule` - Composable policy definitions
- `ComplianceEngine` - Automated compliance mapping
  - EU AI Act
  - SOC 2
  - HIPAA
  - GDPR
- `AuditLog` - Comprehensive audit logging
- `ShadowMode` - Pre-production red-teaming with <2% divergence target

#### Layer 4: Reward & Learning Engine
- `RewardEngine` - Behavioral reward scoring
- `TrustScore` - Per-agent trust scores (0-1000 scale)

#### CLI
- `agentmesh init` - Scaffold a governed agent in 30 seconds
- `agentmesh register` - Register agent with AgentMesh CA
- `agentmesh status` - View agent status and trust score breakdown
- `agentmesh policy` - Load and validate policy files
- `agentmesh audit` - View tamper-evident audit logs

### Dependencies
- Requires `agent-os[nexus,iatp]>=1.2.0` for IATP protocol and Nexus integration
- Python 3.11+ required

### Notes
- This is an alpha release for early adopters and design partners
- API may change before 1.0.0 stable release
- Not recommended for production use without consulting with maintainers
