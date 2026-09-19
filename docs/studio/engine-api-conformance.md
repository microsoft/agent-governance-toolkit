---
title: "Engine API conformance"
last_reviewed: 2026-09-08
owner: studio-team
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Engine API conformance

The Epic 0 conformance profile is the executable compatibility gate for the AGT Studio
Engine API. It treats [`openapi.yaml`](openapi.yaml) as the canonical contract and runs
independent HTTP assertions against the reference FastAPI adapter or a configured external
engine.

## Reference profile

From the repository root, install the `agent-mesh` development dependencies and run:

```text
python -m pytest agent-governance-python/agent-mesh/tests/engine_api/conformance/ -q
```

The default target is an in-process `create_app()` instance backed by an isolated temporary
policy directory. It exercises all 12 HTTP operations, the 11-operation read-only allowlist,
canonical OpenAPI 3.1 response schemas, error envelopes, pagination bounds, policy inventory
and save boundaries, and persistent-state snapshots for read-only requests. The write profile
uses a separate disposable directory and enables save explicitly; the default fixture remains
save-disabled.

The suite uses a real JSON Schema 2020-12 validator for local `$ref` resolution. CI also
installs the local `agent-compliance` replay implementation, the native policy runtime, and
OPA so a successful `POST /api/v1/policy/test` path is exercised rather than treated as proof
when the dependency is absent. Set `AGT_ENGINE_API_REQUIRE_REPLAY=1` to make a missing replay
runtime fail the profile instead of reporting the profile as partial; CI always enables it.

## External engines

Set `AGT_ENGINE_API_URL` to an engine origin to use the reusable transport helpers. The origin
must be user-controlled and disposable when testing writes:

```powershell
$env:AGT_ENGINE_API_URL = "http://127.0.0.1:8080"
$env:AGT_ENGINE_API_OPENAPI = "C:\path\to\engine-openapi.json"
python -m pytest agent-governance-python/agent-mesh/tests/engine_api/conformance/ -q
```

An engine may provide capability metadata without OpenAPI by setting
`AGT_ENGINE_API_METADATA` to a local JSON/YAML metadata document or HTTP URL. The metadata must
identify each operation by method, normalized `/api/v1/...` path, `operationId`, and the three
boolean capability flags. An external run must provision its own policy fixtures and state
visibility before claiming inventory, replay, save, or read-only-state coverage. Missing
provisioning is a partial profile, not unrestricted full-contract conformance.

External runs are read-only by default. They never call `/policy/save`, `/policy/reload`, or
arbitrary advertised operations. Save can trigger a policy reload, and the contract has no
delete endpoint for undoing test writes, so any write exercise requires explicit opt-in and a
disposable target. The reusable external transport also rejects save/reload requests unless
`AGT_ENGINE_API_ALLOW_WRITES=1` is explicitly set.

## Coverage and interpretation

The profile derives the baseline operation set and flags from the checked-in canonical
document; it does not copy the reference route catalog. Target OpenAPI documents may contain
additive operations, but those extensions are validated separately and are never silently
added to the baseline Studio allowlist.

The CI coverage gate measures the reusable helper modules only:
`assertions.py`, `conftest.py`, `contract.py`, and `target.py`. Test modules are excluded from
the measured scope, and the helper total must remain at least 95%.

The following are explicit Epic 0 profile boundaries:

- Non-loopback authentication and token scopes are later sidecar work; a green profile is not
  an authentication certification.
- `/api/v1/events` and its `426 Upgrade Required` WebSocket reservation are deferred to Epic 7a.
- Real trust, audit, agent, and decision backends are not invented for this profile; their
  empty contract-shaped responses are valid.
- The generated Studio-client no-runtime-mutation invariant belongs to Epic 1d.

Schema failures should be interpreted against the canonical document first. In particular,
FastAPI's `{"detail": [...]}` validation response is not an acceptable substitute for the
Engine API error envelope.
