---
title: "AGT Studio sidecar security posture"
last_reviewed: 2026-09-28
owner: studio-team
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AGT Studio sidecar security posture

> **Status:** Proposed implementation gate for Epic 1b; security-minded maintainer
> review required before `agt serve` merges. This is a design, **not** a claim
> that the sidecar or its controls have shipped.
>
> **Scope:** Studio's local authoring/visibility sidecar and its Engine API
> adapter. Runtime governance and the [general AGT threat model](../security/threat-model.md)
> remain separate. The [Engine API contract](engine-api-contract.md) and
> [OpenAPI](openapi.yaml) define the existing wire contract; this document
> identifies additional sidecar requirements and conflicts requiring review.

In this document, **current** means behavior of the shipped
`agentmesh.engine_api.create_app()` reference adapter, **required** means a gate
for a future Studio implementation, and **blocked** means a decision that must
be resolved by the Studio/Engine API owners and a security-minded maintainer.
Conformance to the [Epic 0 profile](engine-api-conformance.md) does **not**
certify sidecar authentication, browser isolation, or workspace authorization.

## Scope and trust boundaries

```text
Human selects local policy workspace
    |                          Untrusted page / same-user process
    v                                      |
Studio SPA (browser) -- HTTP loopback -----+----> agt serve (future)
Studio SPA (IDE) -- postMessage --> webview shell -- HTTP loopback --|
                                                        |
                                          host/origin/auth/route gates
                                                        |
                                          Engine API reference adapter
                                            |             |
                                  policy workspace   engine read sources
                                  + Studio-local log  (audit/trust/decisions)

Remote client -- protected transport / reverse proxy -- explicit non-loopback
  entry (NOT supported for off-host use yet; see "Remote transport")
```

| Boundary / owner | Assets and trust assumption |
| --- | --- |
| Human -> SPA; Studio UI | The user chooses a workspace and explicitly saves. A hidden button or client allowlist does not authorize HTTP callers. Policy source/YAML, replay fixtures, and policy versions can contain secrets. |
| Browser origin -> local TCP listener; Studio sidecar | An untrusted web page can contact loopback; DNS rebinding can make an attacker-controlled host resolve there. Another same-user process can send arbitrary HTTP and forge browser headers. Loopback with no token **cannot identify Studio or isolate it from other processes under the same user**. |
| IDE webview -> shell (`postMessage`); SPA/webview shell (Epic 1c/6) | Validate the sender origin and window/source, message type/schema and correlation ID, and the allowed command on both sides. Never accept arbitrary shell commands or trust page-supplied workspace paths. This boundary is not implemented by the adapter. |
| Bind address / reverse proxy -> sidecar; sidecar + deployment owner | Binding beyond `127.0.0.1` introduces remote clients and potentially a compromised proxy. Proxy headers and reported client addresses are untrusted unless the proxy is explicitly configured and isolated. |
| Credential -> route; Studio sidecar | Remote tokens protect *all* non-exempt routes, not merely the UI. Token/config files are local secrets. Capabilities are descriptive metadata, not an authorization decision. |
| Sidecar -> Engine API / filesystem; sidecar + adapter | Loaded runtime policy state, policy files, configuration and audit/trust/decision data are separate assets. An Engine API policy directory is not automatically an authorized Studio workspace; the process's OS permissions are an upper bound, not the Studio allowlist. |
| Sidecar -> local logs; Studio sidecar + user | The future Studio-local audit/debug logs are user-writable and may reveal policy filenames or usage patterns. They are not the engine's Merkle-backed audit chain. |

The five binding constraints in the
[umbrella tracker](https://github.com/microsoft/agent-governance-toolkit/issues/2729)
apply: (1) runtime state stays read-only, with no approvals,
quarantine, production hot-reload, credential rotation or incident/SOC
operations; (2) the sole user-facing write is policy YAML in an explicitly
selected local workspace; (3) Studio remains the one canonical UI; (4)
visibility serves policy authoring and debugging, not an operator plane; (5)
there is no Studio SSO, SAML, OIDC, RBAC or multi-tenancy. Deployments needing
those controls must provide them outside Studio.

## Binding, credentials, and browser requests

**Current:** The reference adapter CLI binds `127.0.0.1:8080` by default, but
its `--host` option can bind elsewhere without sidecar-level authentication or
TLS. `create_app()` does not authenticate, authorize a workspace, check
browser origins, or write a Studio-local audit record. Save is disabled unless
explicitly enabled by `enable_policy_save=True`,
`AGENTMESH_ENABLE_POLICY_SAVE=1`, or the CLI flag; **enabling it adds no
authentication**. Do not expose this adapter directly on an untrusted network.

**Required for `agt serve`:** Bind only `127.0.0.1` by default; `::1` must
not be bound implicitly. If IPv6 loopback is added, it must be an explicit,
documented loopback-only option with the same browser protections. Never
silently bind wildcard addresses. Non-loopback bind requires deliberate
opt-in **and** a valid credential loaded before the listener starts; absent,
empty, malformed, unreadable or insecurely stored credentials fail startup,
not just individual requests. Only `GET /api/v1/health` and
`GET /api/v1/versions` are unauthenticated on non-loopback per contract
sections [4](engine-api-contract.md#4-authentication) and
[7](engine-api-contract.md#7-endpoint-catalog). An invalid *supplied*
credential is rejected, including on loopback. Missing/invalid remote
credentials yield `401`; an authenticated read-only credential attempting a
write yields `403`. Errors use the contract envelope without echoing secrets.
Do not infer remote identity solely from `X-Forwarded-For`.

### Token protocol proposed for maintainer approval

The following is a **proposal, not a shipped or approved token format**. It
preserves the contract's HTTP `BearerToken` scheme and its read-only/write
distinction without introducing a remote identity system:

- A single, sidecar-owned opaque token is a one-line UTF-8 value of the form
  `agt-studio-v1.<scope>.<random>`, with `<scope>` equal to `read_only` or
  `policy_write` and `<random>` equal to the base64url encoding (without
  padding) of **32 cryptographically random bytes**. The explicit version and scope are
  identifiers, **not** proof of authority: compare the *entire* bearer value
  against the locally configured token in constant time, then use the
  **server-configured** scope. Do not trust a claim parsed from an
  unverified request. Reject unknown versions, scopes, whitespace and
  malformed lengths. One configured credential means no simultaneous
  read-only and write-capable remote users; replacing the credential changes
  scope for all its holders.
- The proposed environment variable is `AGT_STUDIO_TOKEN`. If it is **set**,
  it takes precedence over `~/.config/agt/studio-token`; even an empty or
  malformed value fails closed instead of falling back to the file. Otherwise
  read exactly one token from that file. No token may be conveyed via query
  parameter, URL fragment, command-line argument, response or example.
  Environment variables may be visible to other same-user processes; prefer
  the file. A provisioning action must explicitly generate the secret via the
  operating system's cryptographically secure random generator before remote
  opt-in, never silently at listener startup. The
  sidecar must never print the value.
- The file and its parent directory must be owned by the invoking user,
  non-symlink, and inaccessible to other unprivileged users: Unix directory
  `0700` and file `0600`; on Windows use a per-user directory and explicit
  ACL limited to that user and the OS-required privileged principals, with no
  `Everyone`, `Users`, or `Authenticated Users` access. Verify protections
  before starting, use exclusive creation and atomic replacement, and reject
  permissive permissions instead of proceeding. Do not place the token in a
  repository or world-readable config.
- Default scope is `read_only`. `policy_write` requires a separate explicit
  sidecar save-enable decision **and** an authorized workspace; a token's
  prefix or a valid read-only token alone cannot enable saving. Rotate by
  provisioning a new secret with the same protections and restarting the
  listener; the old value must stop working. Revocation means removing or
  replacing the configured secret and restarting, not merely hiding it in the
  SPA. A single-token design cannot revoke one remote client independently.

The Engine API contract [section 6](engine-api-contract.md#6-read-only-invariant)
says a non-loopback `studio-token` carries a `read_only` scope claim, while its
save endpoint requires write scope. The proposed versioned token above
resolves this via server-verified scope; **the exact encoding, environment
variable, provisioning UX, and whether multiple concurrent scopes are
needed require maintainer/security review** before implementing auth.

### Remote transport: blocked for off-host use

A bearer over plaintext off-host HTTP is not a secure deployment, even with
a strong token. **No off-host non-loopback Studio deployment is supported by
this document or by the current adapter.** Before enabling one, the sidecar
and deployment owners must review a concrete protected transport (TLS at the
listener or a TLS-terminating reverse proxy with an isolated backend), proxy
header and client-address trust, firewall isolation, origin/host allowlists,
token handling at every hop, and protections against bypassing the proxy.
An HTTP backend reachable directly from untrusted clients is not protected
by TLS termination at a proxy. A proxy forwarding to loopback does not make
the loopback no-token exception a remote-auth guarantee; it must enforce
auth on every remote request while the backend is unreachable off-host, or
the design must be revised. A misconfigured/compromised proxy and other
same-user local processes remain residual risks. Until the mode has a
reviewed end-to-end design and negative tests, fail closed rather than treating
explicit bind plus token as sufficient for safe remote use.

### Browser and webview boundary

**Required:** Check `Host` against exact configured listener host(s) and port;
reject attacker hostnames resolving to loopback and malformed/forwarded hosts.
Do not trust `Forwarded` or `X-Forwarded-*` from arbitrary clients. For browser
requests, compare any `Origin` to an explicit exact scheme/host/port allowlist;
reject hostile and `null` origins on **all** methods and preflight, without
reflecting arbitrary origins or sending wildcard CORS with credentials.
Serve the standalone SPA from the same origin where possible. Reject
cross-site `Sec-Fetch-Site` requests; require an allowed `Origin` on POST,
`application/json`, and a non-simple request header checked by the server,
including for `/policy/validate`, `/policy/test`, and `/policy/save`.
Do not rely on a preflight alone: reject simple forms and text/plain requests
at the endpoint. Deny cross-origin reads, not just writes, since policy
content and decisions are sensitive. Configure CSP and avoid caching
sensitive API responses in shared caches. A missing `Origin` on GET is
possible for same-origin navigation and non-browser clients: apply Host,
authentication where applicable, and response/CORS protections rather than
treating it as proof of trust. Browser headers can be forged by local
processes; these controls prevent drive-by web requests, **not** hostile
same-user processes. The webview shell must independently validate
`postMessage` origin, source and schema (Epic 1c/6).

## Route and write boundary

The v1 contract has **12 HTTP operations**: 11 read-only and one write. POST
alone does not imply persistence. The sidecar must enforce route authorization
regardless of capability metadata or the generated client's allowlist.

| Operation | Contract role / sidecar decision |
| --- | --- |
| `GET /api/v1/health` | Read-only; unauthenticated on remote; expose only contract-required status, version and uptime. |
| `GET /api/v1/policies` | Read-only; remote token required; bounded pagination. |
| `GET /api/v1/policies/{id}` | Read-only; remote token required; raw policy content is sensitive. |
| `POST /api/v1/policy/validate` | Read-only computation; remote token required; no persistent write. |
| `POST /api/v1/policy/test` | Read-only computation; remote token required; request-scoped fixtures must be cleaned up on success **and** failure. |
| `POST /api/v1/policy/save` | **Only write**; disabled by default; explicit user gesture, server-enforced workspace and write authorization. |
| `GET /api/v1/audit/log` | Read-only engine audit data; remote token required; **not** the Studio-local save log. |
| `GET /api/v1/trust/scores` | Read-only; remote token required. |
| `GET /api/v1/trust/graph` | Read-only; remote token required. |
| `GET /api/v1/agents` | Read-only; remote token required. |
| `GET /api/v1/decisions` | Read-only; remote token required. |
| `GET /api/v1/versions` | Read-only; unauthenticated on remote; expose required engine/API versions, omit optional environment/capability detail on unauthenticated responses unless explicitly reviewed. |

`POST /api/v1/policy/reload` is excluded from Studio entirely. The
`/api/v1/events` WebSocket reservation is **not** a live HTTP operation;
Epic 7a owns its transport, auth and the contract's deferred HTTP 426 behavior.
No credentials, approvals, quarantine, incident operations or runtime control
are surfaced. The UI's 11-operation read-only allowlist, capability flags and
Save button are defense in depth, not the server authorization boundary.

**Required for authoring (Epic 3):** The user selects a local workspace
explicitly; the sidecar resolves and records an allowlist of canonical roots
selected by that user, with no implicit authorization of the loaded runtime
policy directory. Only policy YAML under those roots may be written from
Studio. The sidecar must enforce the root itself for **every** write; a
request-provided path, ID, format or `policy_dir` override cannot select a
different root. Validate the ID and extension, canonicalize each candidate,
check containment by path components (not string prefix), reject symlinks,
junctions/reparse points and hard-link escapes as appropriate to the
platform, and avoid time-of-check/time-of-use races using safe filesystem
handles and no-follow semantics. Refuse system paths and roots the invoking
user does not own or cannot write; run with least privilege, never setuid/admin.
Do not treat the user's manual workspace selection as permission for the
HTTP client to create or expand that allowlist.

Validate policy content **before** mutation; bound request size, fixture count,
pagination, concurrency and parsing/replay time. Save to a same-directory
temporary file and atomically replace the target; preserve or deliberately
set safe file permissions. Resolve competing edits with a server-checked
version/compare-and-swap under a lock or equivalent atomic scheme; stale
versions must report a conflict without overwriting either edit. The existing
save response has an opaque `version` but its request has **no expected
version field or conditional header**: the wire-level conflict mechanism is
blocked on Engine API owner review, not already provided by the adapter. Changing
`.yaml` to `.yml` or `.json` may remove a sibling file: check, authorize,
audit and make **all** such effects transactional before reporting success.
Never remove a sibling first and then risk failing the target replacement.
Report validation, I/O, conflict and partial-commit failures explicitly.

**Current vs required:** `PolicyRegistry.save()` currently validates the ID,
checks a resolved path under its configured root, writes via a temporary file
and `os.replace`, removes other-format siblings **before** replacing the
target, and re-scans its local registry. It does **not** enforce a selected
Studio workspace, compare versions before writing, or provide the
Studio-local audit guarantee. Its re-scan refreshes an in-process registry;
this is not proof that production enforcement policies were hot-reloaded.
If the adapter is attached to live production state so that saving activates
policies, that conflicts with [ADR 0028](../adr/0028-agt-studio-unified-ui.md)
and must block Studio save until maintainers resolve the architecture. The
contract [section 7.6](engine-api-contract.md#7-endpoint-catalog) and
[section 8](engine-api-contract.md#8-excluded-endpoints) describe saving to
the engine policy directory and a reload side effect;
neither grants Studio permission to hot-reload production policy.

The Engine API wire format permits **YAML and JSON** saves; the umbrella
restricts the **Studio user workflow** to YAML. The SPA must not offer JSON
authoring as a shortcut. Whether the Studio sidecar can reject JSON save
requests while claiming full Engine API conformance, or instead requires a
separate Studio-only write projection, is **blocked pending Engine API and
Studio maintainer review**. Do not silently change the public API or accept
JSON writes as an expansion of Studio scope. Until the workspace, format and
reload conflicts are resolved, keep Studio save disabled, even if the adapter
can be manually opted into saving.

## Local audit, privacy, and diagnostics

**Required in Epic 3:** Write `~/.config/agt/studio-audit.log` for each
attempted policy-file write, including denials and failures. Log a UTC
timestamp, action, result, safe workspace-relative policy identifier,
whether the mutation completed, and an opaque correlation ID; never log
bearer values, policy/fixture contents, request bodies, secrets, sensitive
query values or free-form `commit_message` without a separate redaction
review. Restrict the directory and log to the invoking user (`0700`/`0600`
on Unix; equivalent explicit per-user Windows ACL). Rotate locally at a
defined size (proposed: 10 MiB with five retained files), with documented
retention and a way for the user to inspect/remove old files.

Before a write, durably record intent; if logging or rotation fails, deny
the mutation and surface the error to the UI. After a successful replacement,
record the outcome; if this append fails, **do not return success** or pretend
the mutation rolled back. Surface an indeterminate/partial-completion error,
stop further writes until logging recovers, and let the user inspect the
target. Failure attempts that never changed a file need a result record
where logging is available. Concurrent writes must have unambiguous
ordering. This user-writable local record is **not** the Merkle-backed engine
audit chain from [ADR 0017](../adr/0017-merkle-chain-for-audit-tamper-evidence.md): the local user
can edit or delete it, so it does not provide non-repudiation.

**Required telemetry posture:** No product analytics, remote telemetry
sink or phone-home. Debug logging is **off by default**. A future explicit,
per-process user opt-in may create only
`~/.config/agt/studio-debug.log`, protected like the audit log, with
documented event fields, redaction, rotation and UI/CLI visibility of its
enabled state and path. Disable by ending that opt-in (and on the next
launch, default to off); let the user delete retained local debug files.
Never emit tokens, policy text, fixtures or sensitive response bodies even
in debug mode. This opt-in and log have **not** shipped.

## STRIDE inventory and verification gates

All mitigations below are **requirements for future issues**, not claims
about the reference adapter. Verification belongs to the issue named in the
last column; the Epic 11 sidecar review rechecks them end to end.

| Category | Abuse case / boundary / asset | Required mitigation and owner | Residual risk | Verification |
| --- | --- | --- | --- | --- |
| **Spoofing** | Hostile page or same-user process impersonates Studio; forged/expired or read-only remote bearer gets write scope. Browser -> listener; token -> route. | Sidecar: exact Host/Origin gates and constant-time full-token comparison, scoped route check; SPA/webview shell: source/origin/schema checks. | Same-user processes can forge browser headers or call the no-token loopback listener; no local-client identity claim. | Epic 1b/1c: hostile and `null` origins, spoofed Host/DNS rebinding, missing/invalid/revoked bearer, read-only bearer attempting save, forged webview message. |
| **Tampering** | Traversal, symlink/junction, hard link or concurrent format change writes outside the selected workspace or overwrites a newer policy. Client -> filesystem. | Sidecar/Epic 3: server-owned canonical workspace allowlist, no-follow writes, schema validation, atomic multi-file effects and optimistic conflict checks. | User-authorized edits or external processes can still change files; OS race guarantees differ by platform. | Epic 3: `../`, absolute/sibling path, symlink/junction swap, hard-link, format sibling, invalid content, concurrent CLI/save, interrupted write. |
| **Repudiation** | Write lacks a local record, or user alters it. Save -> Studio log. | Sidecar/Epic 3: durable intent/outcome records, fail closed before mutation if unavailable, report post-commit logging failure. | Local user owns and can edit/delete this non-Merkle log. | Epic 3: successful/denied/failed attempts, log-permission/rotation failure, after-replace append failure, no false success response. |
| **Information disclosure** | Origin bypass or plaintext off-host bearer exposes policy/decision data; error, debug log or public probe leaks secrets. Listener -> remote/browser/log. | Sidecar: reject hostile origins, minimize public probes/errors/logs; deployment owner: no off-host mode without reviewed TLS/proxy isolation. | A malicious same-user process or privileged host actor can still read local data; a compromised proxy can disclose traffic. | Epic 1b/11: cross-origin GET/preflight, public health/version field allowlist, error/log redaction, unprotected HTTP deployment rejected. |
| **Denial of service** | Huge replay fixtures, rapid requests, deep policy parsing or graph queries exhaust local resources. Request -> adapter/engine. | Sidecar + adapter: request/fixture/page bounds, execution timeouts, per-client rate/concurrency limits, bounded errors; no permanently retained test fixtures. | A local same-user process can still consume CPU/disk; no multi-tenant fairness guarantee. | Epic 1b/4/11: oversized inputs, pagination overflow, replay timeout, burst throttling, cleanup after failure/cancel. |
| **Elevation of privilege** | Sidecar runs with elevated file access or a read-only endpoint mutates runtime policy; hidden reload route becomes reachable. Sidecar -> engine/OS. | Sidecar: invoking-user privileges only and server authorization; adapter: preserve read-only persistence and exclude reload; deployment owner: isolate any proxy. | An already privileged local user or compromised engine retains its OS authority. | Epic 1b/1d/11: deny out-of-workspace save, excluded routes, snapshots of all 11 read-only operations (including failure paths), production policy unchanged. |

### Reviewer checklist

- [ ] **Studio/Engine API owners + security-minded maintainer:** approve or explicitly block the token proposal, remote transport, JSON/YAML projection and save/reload conflict below **before** `agt serve` merges.
- [ ] **Sidecar (Epic 1b):** default loopback-only bind; test explicit non-loopback failure without valid/protected credential and without reviewed transport. `/health` and `/versions` remain minimal unauthenticated exceptions.
- [ ] **Sidecar + SPA/webview shell (Epic 1b/1c/6):** reject hostile/`null` origins, forged Host, DNS rebinding, simple POSTs and malicious `postMessage`; verify same-origin and legitimate non-browser paths separately.
- [ ] **Sidecar (Epic 1b/3):** default-off save; test missing/invalid/read-only tokens and enforce exact workspace/YAML scope at the server, not just in the client.
- [ ] **Adapter + client (Epic 1d/7a):** derive 11 read-only HTTP operations, exclude reload and reserved events, snapshot persistence on success and failure, clean replay scratch files. Recheck events when WebSocket work lands.
- [ ] **Sidecar (Epic 3):** test traversal/symlinks, sibling formats, stale versions and interruptions; audit successes/failures and logging outages without leaking secrets or returning false success.
- [ ] **Deployment owner + user (Epic 11):** test protected transport/proxy isolation, local ACLs and log privacy; explicitly accept the same-user, proxy and local-log residual risks.

## Open decisions and dependencies

| Decision / owner | Blocking resolution |
| --- | --- |
| Token encoding, scope, `AGT_STUDIO_TOKEN` and provisioning; Studio owner + security-minded maintainer | Approve or revise the proposed format and secret lifecycle against contract sections 4-6 and OpenAPI `BearerToken`; no self-declared scope may grant a write. |
| Off-host opt-in; Studio owner + deployment/security maintainer | Define and test TLS/proxy, source-address handling and bypass prevention. Until then non-loopback remote use stays blocked; merely enabling a bind and token is not deployment guidance. |
| Studio YAML-only workflow vs contract JSON save; Studio + Engine API owners | Specify how server-side Studio restriction coexists with the v1 public contract before enabling save. |
| Optimistic concurrency vs missing request precondition; Engine API + Studio owners | Define a version precondition and conflict response without silently breaking v1; block Studio save until concurrent external edits cannot be lost. |
| Local registry re-scan vs production reload; Studio + Engine API owners | Prove saving cannot activate production policies, or revise the contract/architecture with maintainer review; do not treat section 8.1 as permission to hot-reload. |
| HTTP `/events` 426 reservation; Engine API owner (Epic 7a) | The spec describes 426, but the reference adapter and Epic 0 conformance profile defer it. Do not count it among 12 operations or claim it is implemented. |

Review against the contract's [transport](engine-api-contract.md#2-transport),
[authentication](engine-api-contract.md#4-authentication),
[capabilities](engine-api-contract.md#5-capability-metadata),
[read-only invariant](engine-api-contract.md#6-read-only-invariant),
[replay and save endpoints](engine-api-contract.md#7-endpoint-catalog),
[exclusions](engine-api-contract.md#8-excluded-endpoints), and
[conformance rules](engine-api-contract.md#9-conformance-rules).

This document does not implement `agt serve`, the workspace picker/save/log
(Epic 3), webview transport (Epic 1c/6), WebSocket (Epic 7a), or the full
sidecar penetration/security review (Epic 11). The Studio package scaffold
and its README are still pending in [#3898](https://github.com/microsoft/agent-governance-toolkit/issues/3898);
add a link back there when that file lands. Any new runtime-control or
public-API semantics require the repository's maintainer decision process,
not a silent interpretation of this document.
