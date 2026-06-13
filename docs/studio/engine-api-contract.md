---
title: "Engine API Contract: AGT Studio v1"
last_reviewed: 2026-06-13
owner: studio-team
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

> **Maintainer note:** This document was originally planned as ADR 0029, referenced in
> [ADR 0028](../adr/0028-agt-studio-unified-ui.md) lines 142-148
> ("Engine API contract is the hard gate"). The decision was made to ship this as a
> versioned spec document rather than a formal ADR so that it can travel alongside the
> implementation PRs in the Studio epic. The intent is preserved: the Engine API
> contract must exist before Studio implementation code lands. Anyone reading ADR 0028
> and looking for the follow-up document it mandated will find it here.

# Engine API Contract: AGT Studio v1

> **Status:** Approved for implementation
> **Date:** 2026-06-13
> **Tracker:** microsoft/agent-governance-toolkit#3011 (Epic 0, issue 1/32)
> **Machine-readable companion:** `docs/studio/openapi.yaml` (OpenAPI 3.1)

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 and RFC 8174.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Transport](#2-transport)
3. [Versioning](#3-versioning)
4. [Authentication](#4-authentication)
5. [Capability Metadata](#5-capability-metadata)
6. [Read-only Invariant](#6-read-only-invariant)
7. [Endpoint Catalog](#7-endpoint-catalog)
8. [Excluded Endpoints](#8-excluded-endpoints)
9. [Conformance Rules](#9-conformance-rules)
10. [Error Model](#10-error-model)
11. [Pagination Model](#11-pagination-model)
12. [Reserved Routes](#12-reserved-routes)
13. [References](#13-references)

---

## 1. Overview

AGT Studio is the single first-class UI for AGT, as decided in ADR 0028. Studio
communicates with a local engine process over a stable HTTP API. This document
defines that API: every route, its purpose, request and response shapes, and
the rules an engine implementation MUST satisfy to be considered conformant.

The engine is a local process started with `agt serve`. The Studio SPA (standalone
or VS Code webview) calls the engine over HTTP for all data operations. A WebSocket
channel (`/api/v1/events`) is reserved for streaming updates and will be defined in
Epic 7a (issue #16).

### 1.1 Scope

**In scope:**

- Every HTTP route exposed to the Studio client, including method, purpose, and
  capability flags
- Full request/response schemas (summarized here; full detail in `openapi.yaml`)
- Capability metadata: the three flags and how the Studio allowlist is derived
- Transport, versioning, auth model, error model, and pagination
- Conformance rules for engine implementations
- Excluded endpoints (routes that exist in existing code but MUST NOT appear in
  the Studio surface)

**Out of scope:**

- FastAPI implementation (issue #3)
- Capability metadata decorator (issue #2)
- Conformance test suite (issue #4)
- WebSocket transport (Epic 7a, issue #16)
- Threat model details (issue #6)

---

## 2. Transport

### 2.1 HTTP for v1

All Studio API traffic uses HTTP/1.1 or HTTP/2 over a loopback TCP connection.
The default listen address is `127.0.0.1:8080`. Engines MUST accept connections
on the loopback interface. Engines MAY also accept connections on non-loopback
interfaces (e.g., for remote Studio access), subject to the authentication
requirements in section 4.

All request and response bodies use `application/json`. Engines MUST set
`Content-Type: application/json` on all JSON responses.

### 2.2 WebSocket reservation

The path `/api/v1/events` is reserved for a WebSocket streaming channel. It MUST
NOT be implemented as an HTTP endpoint. A conformant v1 engine MUST return
`426 Upgrade Required` if a non-WebSocket connection is made to that path. Full
WebSocket semantics are defined in Epic 7a (issue #16).

---

## 3. Versioning

### 3.1 URL versioning

All routes are prefixed with `/api/v1/`. Future breaking changes will use `/api/v2/`,
etc. The version prefix is part of the contract and MUST be preserved.

### 3.2 Version negotiation

The `GET /api/v1/versions` endpoint returns both the engine software version and
the API contract version. Clients SHOULD check `api` equals `1.0.0` on startup
and display an actionable upgrade message if it does not match. Clients MUST NOT
silently degrade when versions mismatch (per ADR 0028 success criteria).

### 3.3 Breaking-change policy

A breaking change is any of the following:

- Removing or renaming an endpoint
- Changing a required request field to a different type or removing it
- Adding a required field to a response schema that clients are expected to parse
- Changing an HTTP method for an existing path
- Changing the capability flags of an existing endpoint

Breaking changes require incrementing the URL version (`/api/v2/`). The previous
version MUST remain available for at least one full release cycle after the new
version ships. Additive changes (new optional fields, new endpoints) do not
require a version bump.

---

## 4. Authentication

### 4.1 Loopback connections (no token required)

When the Studio client connects from `127.0.0.1` or `::1`, no authentication
token is required. The engine MAY still check that the token is absent or valid
if one is provided.

### 4.2 Non-loopback connections (token required)

When the Studio client connects from any address other than the loopback, the
engine MUST require a Bearer token. The client reads the token from
`~/.config/agt/studio-token`. Requests without a valid token MUST be rejected
with `401 Unauthorized`.

The token format and rotation policy are defined in the threat model (issue #6).

### 4.3 Scope

The `GET /api/v1/health` and `GET /api/v1/versions` endpoints MUST be accessible
without authentication even on non-loopback interfaces. All other endpoints
require authentication on non-loopback connections.

---

## 5. Capability Metadata

### 5.1 The three flags

Every endpoint in this contract carries three boolean capability flags. These
flags are authoritative: they define the behavioral contract of the endpoint, not
just documentation.

| Flag | Type | Meaning |
|------|------|---------|
| `runtime_mutating` | boolean | The endpoint persists a change to engine state (writes to disk, modifies loaded policy, changes trust state, etc.). |
| `user_intent_required` | boolean | The endpoint MUST only be invoked in response to an explicit user gesture (button click, confirm dialog). It MUST NOT be called speculatively or in a background job. |
| `read_only_surface` | boolean | The endpoint is safe to expose on a read-only Studio surface (guest viewer, demo mode, CI surface). An endpoint is read-only if and only if `runtime_mutating == false`. |

Flags are declared in `openapi.yaml` as the `x-capability-flags` extension on each
operation object. Engine implementations MUST expose these flags via
`GET /api/v1/versions` in a `capabilities` array if they wish to advertise
extended support.

### 5.2 Flag values by endpoint

| Route | Method | `runtime_mutating` | `user_intent_required` | `read_only_surface` |
|-------|--------|--------------------|------------------------|---------------------|
| `/api/v1/health` | GET | false | false | true |
| `/api/v1/policies` | GET | false | false | true |
| `/api/v1/policies/{id}` | GET | false | false | true |
| `/api/v1/policy/validate` | POST | false | false | true |
| `/api/v1/policy/test` | POST | false | false | true |
| `/api/v1/policy/save` | POST | **true** | **true** | **false** |
| `/api/v1/audit/log` | GET | false | false | true |
| `/api/v1/trust/scores` | GET | false | false | true |
| `/api/v1/trust/graph` | GET | false | false | true |
| `/api/v1/agents` | GET | false | false | true |
| `/api/v1/decisions` | GET | false | false | true |
| `/api/v1/versions` | GET | false | false | true |
| `/api/v1/events` | WS | false | false | true |

Exactly one endpoint has `runtime_mutating: true`: `POST /api/v1/policy/save`.

`/api/v1/events` is a reserved WebSocket route (see section 12). It carries
read-only flags but is not implemented in v1 and is excluded from the client
allowlist below.

---

## 6. Read-only Invariant

### 6.1 Definition

**Invariant:** No operation with `read_only_surface: true` may have a permanent
side effect on engine state. Specifically:

- No file writes (including policy files, config, or audit sinks)
- No policy reload triggered as a side effect of the request
- No trust-state mutations (trust score changes, capability grants, DID registry
  changes)

Memory-only state changes that do not survive a process restart (e.g., caching a
computed query result in RAM) are acceptable and do not violate this invariant.

Note that `POST /api/v1/policy/validate` and `POST /api/v1/policy/test` both use
the `POST` method and accept a body. They are still `read_only_surface: true`
because they perform computation only: no state persists after the response
completes.

### 6.2 Worked example: client-allowlist derivation

A Studio surface configured for read-only access (guest viewer, demo mode, or a
CI read-only check) builds its allowlist as follows:

1. Iterate over all operations in the Engine API endpoint catalog.
2. Keep only operations where `read_only_surface == true`.
3. Block the client from calling any operation not in this list.

Applying this rule to AGT Studio v1:

**Allowlisted (11 operations):**

- `GET /api/v1/health`
- `GET /api/v1/policies`
- `GET /api/v1/policies/{id}`
- `POST /api/v1/policy/validate`
- `POST /api/v1/policy/test`
- `GET /api/v1/audit/log`
- `GET /api/v1/trust/scores`
- `GET /api/v1/trust/graph`
- `GET /api/v1/agents`
- `GET /api/v1/decisions`
- `GET /api/v1/versions`

**Blocked (1 operation):**

- `POST /api/v1/policy/save` (`runtime_mutating: true, read_only_surface: false`)

Reserved routes (the WebSocket `/api/v1/events` channel in section 12) are
excluded from the v1 allowlist entirely: they are not callable operations in v1,
so they appear in neither the allowlisted nor the blocked set above. The math
covers the 12 implemented HTTP operations only.

The Studio client enforces this allowlist at the UI layer: "Save" controls are
not rendered in read-only mode. The engine enforces it at the auth layer: the
`studio-token` for non-loopback connections carries a `read_only` scope claim.
Detailed token scoping is in the threat model (issue #6).

---

## 7. Endpoint Catalog

All routes are relative to the `/api/v1/` base path. Request and response schemas
are summarized here; full JSON Schema definitions are in `openapi.yaml`.

### 7.1 GET /api/v1/health

**Purpose:** Liveness probe. Reports engine status and version.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Auth:** Not required (loopback or non-loopback).

**Response (200):**

| Field | Type | Description |
|-------|------|-------------|
| `status` | `"ok"` or `"degraded"` | Engine health status |
| `version` | string | Engine software version (e.g., `"0.3.0"`) |
| `uptime_seconds` | number | Seconds since engine process start |

---

### 7.2 GET /api/v1/policies

**Purpose:** List all policies currently loaded in the engine. Fixes the
counts-only gap in the existing `policy_server.py` `GET /api/v1/policies`
implementation (which currently returns only totals, not policy objects).

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Query parameters:** `page`, `limit` (see section 11).

**Response (200):** Paginated list of `PolicySummary` objects.

`PolicySummary` fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier derived from filename |
| `name` | string | Human-readable policy name |
| `format` | `"yaml"` or `"json"` | File format |
| `source` | string | File path relative to policy directory |
| `description` | string (optional) | Policy description if present in file |

---

### 7.3 GET /api/v1/policies/{id}

**Purpose:** Retrieve full detail for a single policy.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Path parameter:** `id` - Policy identifier.

**Response (200):** `PolicyDetail` object (all `PolicySummary` fields plus):

| Field | Type | Description |
|-------|------|-------------|
| `content` | string | Raw policy file content |
| `rules_count` | integer | Number of rules in the policy |
| `last_modified` | string (date-time) | Last modification timestamp of the policy file |

**Response (404):** Error envelope with `code: "POLICY_NOT_FOUND"`.

---

### 7.4 POST /api/v1/policy/validate

**Purpose:** Lint and parse a policy document. No side effects; computation only.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | yes | Raw policy content to validate |
| `format` | `"yaml"` or `"json"` | yes | Format of the content |

**Response (200):**

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | True if the policy parses and passes all lint rules |
| `errors` | array of `ValidationError` | Parse or lint errors (empty when valid) |

`ValidationError` fields: `line` (integer), `col` (integer), `message` (string).

---

### 7.5 POST /api/v1/policy/test

**Purpose:** Run regression fixtures against loaded policies. Wraps the
`policy_test.replay` engine from `agent-compliance`. No side effects; computation
only.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fixtures` | array of `FixtureInput` | yes | Inline fixtures to execute |
| `policy_dir` | string | no | Policy directory override (defaults to engine `policy_dir`) |

`FixtureInput` fields: `id` (string), `input` (object), `expected_verdict` (enum),
`expected_rule` (string, optional).

**Response (200):**

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total fixtures run |
| `passed` | integer | Fixtures that matched expected verdict |
| `failed` | integer | Fixtures that did not match |
| `results` | array of `FixtureResult` | Per-fixture outcomes |

`FixtureResult` fields: `fixture_id`, `passed`, `expected_verdict`,
`actual_verdict`, `expected_rule` (optional), `actual_rule` (optional),
`fixture_path` (optional), `resolution_metadata` (object, optional).

The engine adapts the inline `fixtures` array into the form the existing
`policy_test.replay` helper expects (which reads policy and fixture files from
disk) by materializing the inline fixtures into a temporary working directory
for the duration of the request, then discarding it. No caller-visible files are
created and no engine state is mutated.

---

### 7.6 POST /api/v1/policy/save

**Purpose:** Persist a new or updated policy to the engine's policy directory. This
is the single write endpoint in the Studio surface.

**Capability flags:** `runtime_mutating: true`, `user_intent_required: true`,
`read_only_surface: false`

The `user_intent_required: true` flag means the Studio client MUST only call this
endpoint from a direct user gesture (clicking a "Save" or "Publish" button). It
MUST NOT be called speculatively, from a timer, or as a background side effect.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Policy identifier (becomes filename). Pattern: `^[a-z0-9][a-z0-9_-]{0,63}$` |
| `content` | string | yes | Policy content to persist |
| `format` | `"yaml"` or `"json"` | yes | File format to write |
| `commit_message` | string | no | Human description for the audit log (max 512 chars) |

**Response (200):**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Saved policy identifier |
| `saved_at` | string (date-time) | Timestamp of the save |
| `version` | string | Opaque version token for optimistic concurrency |

**Response (401):** Unauthenticated non-loopback request.
**Response (403):** Token present but lacks write scope.

---

### 7.7 GET /api/v1/audit/log

**Purpose:** Retrieve paginated audit log entries from the engine's in-memory and
persistent audit store.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Query parameters:** `page`, `limit` (see section 11), plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_did` | string | Filter to a single agent DID |
| `from` | string (date-time) | Earliest entry timestamp (inclusive) |
| `to` | string (date-time) | Latest entry timestamp (inclusive) |

**Response (200):** Paginated list of `AuditLogEntry` objects.

`AuditLogEntry` fields:

| Field | Type | Description |
|-------|------|-------------|
| `entry_id` | string | Unique entry identifier |
| `timestamp` | string (date-time) | Entry timestamp |
| `agent_did` | string | Acting agent DID |
| `action` | string | Action performed |
| `outcome` | `"success"`, `"failure"`, `"denied"` | Result |
| `resource` | string (optional) | Target resource |
| `target_did` | string (optional) | Target agent DID |
| `policy_decision` | string (optional) | Policy verdict that produced this entry |
| `entry_hash` | string | SHA-256 hash for Merkle chain integrity (see ADR 0017) |

---

### 7.8 GET /api/v1/trust/scores

**Purpose:** List trust scores for all known agents, or for a specific agent.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Query parameters:** `page`, `limit`, `agent_did` (filter to one agent).

**Response (200):** Paginated list of `TrustScoreItem` objects.

`TrustScoreItem` fields:

| Field | Type | Description |
|-------|------|-------------|
| `agent_did` | string | Agent DID |
| `trust_score` | integer (0-1000) | Numeric trust score |
| `trust_level` | enum | `untrusted`, `probationary`, `standard`, `trusted`, `verified_partner` |
| `last_updated` | string (date-time, optional) | When the score was last changed |

---

### 7.9 GET /api/v1/trust/graph

**Purpose:** Return the full trust graph: all agents as nodes and all trust/
delegation relationships as directed edges. Useful for the Studio graph
visualization panel.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Response (200):** `TrustGraph` object.

| Field | Type | Description |
|-------|------|-------------|
| `nodes` | array of `TrustGraphNode` | Agents (did, trust_score, name) |
| `edges` | array of `TrustGraphEdge` | Directed relationships (from_did, to_did, relationship, weight) |

Relationship values: `"trusts"`, `"delegates"`, `"sponsors"`.

---

### 7.10 GET /api/v1/agents

**Purpose:** List registered agents and their metadata.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Query parameters:** `page`, `limit`.

**Response (200):** Paginated list of `AgentSummary` objects.

`AgentSummary` fields:

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | Agent DID (`did:mesh:...`) |
| `name` | string (optional) | Human-readable name |
| `trust_score` | integer (0-1000) | Current trust score |
| `trust_level` | enum | `untrusted`, `probationary`, `standard`, `trusted`, `verified_partner` |
| `last_active` | string (date-time, optional) | Timestamp of most recent event |
| `capabilities` | array of string | List of granted capability strings |

---

### 7.11 GET /api/v1/decisions

**Purpose:** Retrieve recent policy decisions as an HTTP-poll endpoint. In v1 the
client polls this endpoint; in Epic 7a the same decisions will also stream over
the WebSocket channel at `/api/v1/events`.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Query parameters:** `page`, `limit`, plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_did` | string | Filter by agent DID |
| `verdict` | enum | Filter by verdict: `allow`, `deny`, `warn`, `require_approval` |

**Response (200):** Paginated list of `Decision` objects.

`Decision` fields:

| Field | Type | Description |
|-------|------|-------------|
| `decision_id` | string | Unique decision identifier |
| `timestamp` | string (date-time) | When the decision was made |
| `agent_did` | string | Acting agent DID |
| `action` | string | Action that was evaluated |
| `resource` | string (optional) | Target resource |
| `verdict` | enum | `allow`, `deny`, `warn`, `require_approval` |
| `matched_rule` | string (optional) | Name of the rule that produced the verdict |
| `policy_name` | string (optional) | Name of the policy that matched |
| `reason` | string | Human-readable reason for the verdict |

---

### 7.12 GET /api/v1/versions

**Purpose:** Report engine software version and API contract version. Used by
clients to detect version mismatches.

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`

**Auth:** Not required (loopback or non-loopback).

**Response (200):**

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | Engine software version (e.g., `"0.3.0"`) |
| `api` | string | API contract version (e.g., `"1.0.0"`) |
| `python` | string (optional) | Python runtime version |
| `capabilities` | array of string (optional) | Supported capability identifiers |

---

## 8. Excluded Endpoints

The following routes appear in existing engine code but MUST NOT be exposed through
the Studio surface.

### 8.1 POST /api/v1/policy/reload

**Source:** `policy_server.py`, line 178.

**Rationale for exclusion:** This endpoint reloads all policy files from disk
without requiring user intent. It is `runtime_mutating: true` and would need to be
`user_intent_required: true` to appear in the Studio contract. However, policy
reload has no safe Studio use case: the `POST /api/v1/policy/save` endpoint already
triggers a reload as a side effect of saving. Exposing a standalone reload button
in the Studio UI would create a dangerous pattern (reloading with no visible change to the
user). The endpoint remains available as an internal sidecar-management endpoint
but is explicitly excluded from this contract and from the Studio allowlist.

Engines that implement the Studio surface MUST NOT route `POST /api/v1/policy/reload`
through the Studio auth path.

---

## 9. Conformance Rules

An engine implementation is conformant with this contract when ALL of the following
hold:

1. **Route presence:** Every route in section 7 exists and responds to its
   specified HTTP method. A `404` on any specified route is a conformance failure.

2. **Schema compliance:** Request and response bodies match the schemas in
   `openapi.yaml`. Extra optional fields are permitted in responses. Missing
   required fields are a conformance failure.

3. **Capability flags declared:** Every operation exposes its `x-capability-flags`
   values in the OpenAPI document generated by the engine (if the engine generates
   one). Engines that do not generate an OpenAPI document MUST document flags
   elsewhere; the values MUST match section 5.

4. **Read-only invariant holds:** Every endpoint with `runtime_mutating: false`
   MUST NOT produce permanent side effects (see section 6.1).

5. **Exactly one write endpoint:** Only `POST /api/v1/policy/save` has
   `runtime_mutating: true`. If an engine exposes additional mutating endpoints
   on the `/api/v1/` prefix, they MUST be documented and their flags MUST be
   declared accordingly.

6. **Excluded endpoint absent:** `POST /api/v1/policy/reload` MUST NOT be reachable
   through the Studio auth path (section 8.1).

7. **Error envelope:** All error responses MUST use the envelope schema defined in
   section 10.

8. **Pagination:** All list endpoints that carry pagination query parameters MUST
   return a `pagination` object in the response matching section 11.

9. **Version endpoint accurate:** `GET /api/v1/versions` MUST return the correct
   `api` value (`"1.0.0"` for this contract version). Mismatched values are a
   conformance failure.

10. **Authentication enforced:** Non-loopback connections to endpoints other than
    `/health` and `/versions` MUST be rejected with `401` when no valid token is
    provided.

The conformance test suite is defined in issue #4.

---

## 10. Error Model

### 10.1 Status codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Malformed request (invalid JSON, missing required field) |
| 401 | Unauthenticated (non-loopback, no token) |
| 403 | Forbidden (token present but insufficient scope) |
| 404 | Resource not found |
| 422 | Request body is syntactically valid JSON but semantically invalid |
| 429 | Rate limit exceeded |
| 500 | Internal engine error |
| 503 | Engine not ready (startup or degraded) |

### 10.2 Error envelope schema

All error responses MUST use this JSON envelope regardless of status code:

```json
{
  "status": 404,
  "code": "POLICY_NOT_FOUND",
  "message": "Policy with id 'my-policy' not found",
  "details": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | integer | yes | HTTP status code (mirrors the HTTP response status) |
| `code` | string | yes | Machine-readable code in `SCREAMING_SNAKE_CASE` |
| `message` | string | yes | Human-readable description safe to display in the UI |
| `details` | object | no | Endpoint-specific diagnostic information |

### 10.3 Standard error codes

| Code | Status | Context |
|------|--------|---------|
| `POLICY_NOT_FOUND` | 404 | Requested policy ID does not exist |
| `POLICY_PARSE_ERROR` | 422 | Policy content failed to parse |
| `FIXTURE_LOAD_ERROR` | 422 | A fixture in a test request is malformed |
| `VALIDATION_ERROR` | 422 | Request body field validation failed |
| `UNAUTHORIZED` | 401 | No token provided on non-loopback connection |
| `FORBIDDEN` | 403 | Token present but lacks required scope |
| `RATE_LIMITED` | 429 | Too many requests; retry after the `Retry-After` header value |
| `ENGINE_UNAVAILABLE` | 503 | Engine is starting up or in degraded state |
| `INTERNAL_ERROR` | 500 | Unexpected engine error |

---

## 11. Pagination Model

### 11.1 Query parameters

All list endpoints that support pagination accept these query parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | 1-based page number |
| `limit` | integer | 20 | Items per page (minimum 1, maximum 100) |

### 11.2 Response object

Paginated responses MUST include a top-level `pagination` object:

```json
{
  "items": [ ... ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 87,
    "has_next": true
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `page` | integer | Current page number (1-based) |
| `limit` | integer | Items per page |
| `total` | integer | Total number of items across all pages |
| `has_next` | boolean | Whether more pages exist after this one |

### 11.3 Paginated endpoints

The following endpoints MUST implement the pagination model:

- `GET /api/v1/policies`
- `GET /api/v1/audit/log`
- `GET /api/v1/trust/scores`
- `GET /api/v1/agents`
- `GET /api/v1/decisions`

---

## 12. Reserved Routes

### 12.1 WebSocket: /api/v1/events

The path `/api/v1/events` is reserved for a WebSocket streaming channel that will
deliver real-time policy decisions, agent events, and trust updates to the Studio
client.

**This endpoint is not implemented in v1.** It will be fully defined in Epic 7a
(issue #16).

**Capability flags:** `runtime_mutating: false`, `user_intent_required: false`,
`read_only_surface: true`. The route carries read-only flags because the future
stream is a read-only push channel, but because it is reserved and not callable
in v1 it is excluded from the client allowlist derived in section 6.2.

Conformance requirement: a v1 engine MUST return `426 Upgrade Required` when an
HTTP (non-WebSocket) request is made to `/api/v1/events`. The engine MUST NOT
implement this path as an HTTP endpoint.

---

## 13. References

- [ADR 0028: AGT Studio, a single unified UI for governance](../adr/0028-agt-studio-unified-ui.md) (the binding scope document)
- `docs/studio/openapi.yaml` (OpenAPI 3.1 machine-readable companion to this document)
- `agent-governance-python/agent-mesh/src/agentmesh/server/sidecar.py` (existing sidecar surface)
- `agent-governance-python/agent-mesh/src/agentmesh/server/policy_server.py` (existing policy server)
- `agent-governance-python/agent-mesh/src/agentmesh/server/audit_collector.py` (existing audit collector)
- `agent-governance-python/agent-mesh/src/agentmesh/server/trust_engine.py` (existing trust engine)
- `agent-governance-python/agent-mesh/src/agentmesh/dashboard/api.py` (existing dashboard backend)
- `agent-governance-python/agent-compliance/src/agent_compliance/policy_test.py` (replay engine wrapped by `/policy/test`)
- Issue #2: Capability metadata decorator implementation
- Issue #3: FastAPI implementation
- Issue #4: Conformance test suite
- Issue #6: Threat model and token security
- Issue #16 (Epic 7a): WebSocket transport definition
