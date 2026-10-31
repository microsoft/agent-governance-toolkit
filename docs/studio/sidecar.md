---
title: "Studio loopback sidecar (draft)"
last_reviewed: 2026-10-13
owner: studio-team
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Studio loopback sidecar (draft)

**Status: proposed implementation of #4281, stacked above unmerged #4170.**
Neither the scaffold nor this layer is represented as shipped on `main`.
The Studio owners (@MohammadHaroonAbuomar, @liamcrumm, @prayagupa), Engine API
owners and a security-minded maintainer must review the implementation, browser
contract, process isolation and error mappings before merge. The
[security posture](sidecar-security-posture.md) remains an approval gate, not
a certification.

## Install the real backend

The compliance distribution provides `agt`; the core wheel includes
`agentmesh.engine_api`. Do not install the deprecated mesh distribution or
substitute the similarly named toolkit CLI distribution. Native ACS `0.4.0b0`
is not yet on the public index: build it from the same checkout, rather than
downgrading to an incompatible published release. Python 3.11+, Rust and its
platform linker are required for this source build.

From the repository root (PowerShell):

```powershell
python -m venv .venv-studio
$python = ".\.venv-studio\Scripts\python.exe"
$env:PATH = "$(Resolve-Path .venv-studio\Scripts);$env:PATH"
& $python -m pip install build==1.6.1 setuptools==83.0.0 wheel==0.46.3 hatchling==1.28.0 maturin==1.8.7
& $python -m pip wheel --no-deps --no-build-isolation --wheel-dir .studio-wheels .\policy-engine\sdk\python
& $python -m build --no-isolation --wheel --outdir .studio-wheels agent-governance-python\agent-governance-toolkit-core
& $python -m build --no-isolation --wheel --outdir .studio-wheels agent-governance-python\agent-compliance
& $python -m build --no-isolation --wheel --outdir .studio-wheels agent-governance-studio
$wheels = Get-ChildItem .studio-wheels\*.whl | ForEach-Object FullName
& $python -m pip download --dest .studio-wheelhouse -c agent-governance-studio\runtime-constraints.txt $wheels
& $python -m pip install --no-index --find-links .studio-wheelhouse agent-governance-studio==5.0.0
```

Use OPA `0.70.0`, verify its SHA-256 before executing it, and set `ACS_OPA_PATH`
to the executable. The upstream Windows AMD64 asset is
`https://github.com/open-policy-agent/opa/releases/download/v0.70.0/opa_windows_amd64.exe`
(SHA-256 `19d00eea60477a8f983c20af690fedcc8da52aef81922e570b27538ca88305a4`).
The existing CI uses Linux AMD64 static OPA from
`https://openpolicyagent.org/downloads/v0.70.0/opa_linux_amd64_static`
(SHA-256 `00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084`).
No startup download or automatic native dependency repair occurs.

To reproduce clean-install tests, point `AGT_STUDIO_TEST_WHEELHOUSE` at the
wheelhouse and run the README's Python test command in the installed environment.
The clean-install test creates another environment outside the checkout, with
neither development extras nor `PYTHONPATH`, and uses the real CLI/plugin,
core wheel, compliance replay, native ACS and OPA.

## Supported command and configuration

```text
agt serve --help
agt serve
agt serve --host 127.0.0.1 --port 8080 --policy-dir <directory>
```

The default is exactly `http://127.0.0.1:8080`, foreground only. The host must be
literal `127.0.0.1`; `localhost`, other IPv4 loopback aliases, IPv6, wildcard
and off-host addresses fail before binding. Ports are integers from 1 to 65535.
There is no auto-selected replacement port, browser opening, reloader, daemon,
token argument or save-enable switch.

Policy-root precedence is explicit `--policy-dir`, then `AGT_STUDIO_POLICY_DIR`,
then **deliberately empty inventory**. An explicitly empty, missing, non-directory
or unreadable root fails startup. `AGENTMESH_POLICY_DIR` and the adapter's Unix
fallback are not used. `AGENTMESH_ENABLE_POLICY_SAVE` cannot enable Studio writes.
`AGT_STUDIO_TOKEN`, including an empty value, or an existing
`~/.config/agt/studio-token` fails startup: credential provisioning/verification
is not implemented or approved for this profile.

Startup bounds and snapshots the selected tree into private, process-owned
temporary storage, preserving content and modification timestamps. This keeps
the loaded inventory, pagination and policy metadata stable for the server's
lifetime. Restart to observe external edits; there is no reload endpoint.
Replay root overrides must resolve inside the selected source root and are
mapped to its corresponding snapshot subtree. The source/persistent policy,
config, audit and trust files are never written. Links/junctions inside the
tree are rejected. This is not an authoring workspace or an OS sandbox.

Initialization performs a real native ACS/OPA replay before binding. A missing
or incompatible backend, invalid root, startup deadline or bind collision exits
nonzero with a sanitized diagnostic, never a ready message. Readiness is
reported only after ASGI startup and actual socket binding succeed.

## Proposed HTTP client contract

This contract is implemented in the draft and **pending Studio/Engine API/security
owner review**, especially later SPA/webview origin integration:

- Every request must use exact `Host: 127.0.0.1:<configured-port>`, including
  the explicit port. Supplied Origins must parse to the exact HTTP listener
  origin, with no userinfo, path, query or fragment. For port 80, the standard
  implicit-port Origin is also accepted; Host still requires `:80`.
- `null`/hostile Origins, duplicate security headers, `Forwarded`, any
  `X-Forwarded-*`, and `Sec-Fetch-Site` other than `same-origin`/`none` are rejected.
  There is no proxy trust or remote exception.
- All POSTs, including validation/replay, require the allowed Origin,
  `Content-Type: application/json` and **`X-AGT-Studio-Request: 1`**.
  Simple forms, text bodies and encoded/compressed bodies are rejected.
- OPTIONS validates the same boundary, registered method and exact allowed
  requested header set. It does not reflect arbitrary origins or allow
  credentials. Supplied Authorization, cookies, API-key/token headers and
  recognized credential query parameters fail closed (`401 UNAUTHORIZED`).

An explicit non-browser caller may omit Origin on GET but must supply the same
headers as a browser on POST:

```powershell
$origin = "http://127.0.0.1:8080"
Invoke-RestMethod "$origin/api/v1/health"
$headers = @{ Origin = $origin; "X-AGT-Studio-Request" = "1" }
$body = @{ content = "name: Example`nrules: []"; format = "yaml" } | ConvertTo-Json
Invoke-RestMethod "$origin/api/v1/policy/validate" -Method Post -ContentType application/json -Headers $headers -Body $body
```

Missing Origin on GET is not proof of trusted identity. Same-user processes can
forge all these headers and read the loopback API; the profile prevents drive-by
browser abuse, **not hostile same-user processes**.

The generated canonical OpenAPI retains all 12 operations, capability flags and
error schemas; the 11-operation read-only projection is metadata-derived.
Save remains registered but always returns `403 FORBIDDEN` after valid outer
gates, for both YAML and JSON, without creating an audit log or persistent write.
Reload/events/runtime control are absent. `/openapi.json`, error responses and
preflight receive the same boundary/privacy protections. HTML docs/redoc are
disabled; no SPA is served, so no claim is made that API headers provide a
future SPA's CSP.

## Finite budgets and proposed errors

| Budget | Default / behavior |
| --- | --- |
| Wire body (Content-Length or chunked/streamed) | 8 MiB inclusive; one byte over yields `413 VALIDATION_ERROR` |
| Request target | Path 1024 characters, query 2048 bytes; excess yields `422 VALIDATION_ERROR` |
| Canonical policy text / replay fixture count | 1,048,576 characters / 1–1000 fixtures; original `422 VALIDATION_ERROR` field semantics |
| Pagination | Original page ≥1 and limit 1–100; original envelopes |
| Selected tree | 256 file/directory entries, 1 MiB per file, 16 MiB total file bytes; startup fails over any bound |
| Response body | 16 MiB in the worker; excess fails without partial success |
| General admission | Two concurrent requests; 60 admitted attempts per rolling minute, process-global in-memory bookkeeping |
| Reserved health/version admission | One concurrent probe; independent 120/minute budget |
| Body receive / adapter execution | 5 / 10 seconds, including parsing/imports/replay; `408 VALIDATION_ERROR` / `504 ENGINE_UNAVAILABLE` |
| Backend initialization | 10 seconds, including snapshotting and real startup replay |
| Worker reaping / shutdown | Worker tree killed and reaped within 2 seconds; cancellation/cleanup budget 3 seconds plus ASGI grace ≤3 seconds |

These are fixed finite profile defaults, not CLI bypass switches. Request workers
compose the actual `create_app(policy_dir=..., enable_policy_save=False)` and
execute its real ASGI handlers. Short-lived workers trade throughput for reliable
cancellation; startup snapshots and a common monotonic start time preserve
server-lifetime semantics. They are not unrestricted module runners, thread
timeouts or fabricated replay services. Separate probe admission keeps health
responsive while computation capacity is occupied.

`413`, `408` and `504` with these existing canonical codes are **proposed additive
Studio mappings**, not already approved Engine API semantics. `429 RATE_LIMITED`
includes `Retry-After: 60`; backend request failures use `503 ENGINE_UNAVAILABLE`.
Canonical parse errors, typed invalid-policy results and field validation remain
distinct. Validation details retain field locations/types, but input values,
parser context and sensitive paths are redacted; owners must review this privacy
projection. The canonical contract/schema assertions are not weakened.

## Lifecycle and privacy

Ctrl+C / graceful termination stops accepting requests, cancels owned work,
kills the entire request process tree, reaps it, removes request/snapshot scratch
storage and releases the port. The foreground sidecar consumes graceful SIGINT
and SIGTERM after cleanup and exits successfully, restoring prior signal handlers
instead of re-raising a shutdown signal. Windows uses kill-on-close Job Objects;
POSIX uses owned process sessions. Windows console Ctrl+Break is also supported
for targeted graceful termination. Immediate OS force-kill/power loss cannot
guarantee Python scratch cleanup; Windows Jobs still contain/terminate descendants.
Do not mistake `TerminateProcess` for a graceful signal.

All API, error and preflight responses have `Cache-Control: no-store, private`,
`Pragma: no-cache`, `Expires: 0`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. Access logs, debug
telemetry and analytics are off; `agt --verbose serve` does not opt into file
logging. Diagnostics use fixed labels and do not include query/body/token values
or raw engine tracebacks. The only local writes are owned temporary snapshots and
request-scoped fixture materialization, not a persistent audit/telemetry sink.

## Pending merge gates and prior art

The scaffold must merge first. Studio owners, Engine API owners and a
security-minded maintainer must review this profile's browser contract, fixed
budgets, process lifecycle, snapshot semantics and additive error/privacy
projection. Token encoding/provisioning, off-host TLS/proxy isolation, authoring
workspace/YAML-vs-JSON/concurrency/activation, save auditing and events remain
blocked/deferred, not checked-off approvals.

This composition reuses AGT's existing Engine API/Click plugin/ACS replay designs;
server lifecycle uses Uvicorn and process-tree containment uses Python's process
sessions and Microsoft's documented Windows Job Objects. No external
implementation is copied. See the [canonical contract](engine-api-contract.md)
and [independent conformance profile](engine-api-conformance.md); green Epic 0
tests are not security certification.
