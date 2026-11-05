---
title: "AGT and Governance Substrate"
last_reviewed: 2026-10-30
owner: community
---

# AGT and Governance Substrate

<!-- cspell:ignore basetemp -->

> Status: experimental, community-maintained example for RFC #4298.

This optional example puts AGT's native policy enforcement before independent
Governance Substrate authorization and execution. Both must permit an action.
It changes no AGT core package, replaces no policy logic, and requires no model,
API key, paid service, or internet connection at runtime.

## Architecture

```text
Untrusted Docker worker (no network; non-root; read-only root)
    -> permitted Unix tool socket
    -> trusted AGT controller: run_tool(..., mode=ENFORCE)
    -> Governance Substrate /authorizations: independent permission check
    -> one-use grant -> /executions -> local SMTP/HTTP/file effect

Trusted operator -> AGT KillSwitch callback -> authenticated stop handler
    -> Substrate.set_circuit() -> Docker supervisor
    -> confirmed exit/removal of the bound immutable worker ID
```

The controller passes only AGT's approved effective arguments. An AGT denial
never reaches substrate authorization; a substrate denial never reaches
execution. Human approval is bound to the exact action, not a general override.

Evidence ties the call ID, DID and session to the native AGT decision, substrate
authorization event, grant hash, execution event, generation/container IDs, and
shutdown receipt. Raw grants and credentials are never returned to the worker.

## Prerequisites and Build

- Docker Engine with Compose and Linux containers (tested on Docker Desktop).
- Python 3.12 and Git on the trusted host; pytest for the deployment regressions.
- A **clean local checkout** of [Governance Substrate v0.7.0](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/releases/tag/v0.7.0)
  at `03f715bde3f5f28c39870090036dc02e0e147f50`.

Supply the external checkout explicitly; the scripts never clone or download it.
Read [NOTICE.md](NOTICE.md) for ownership and the external AGPL license boundary.
The external source is mounted read-only, not copied into AGT or its core packages.

From the AGT repository root:

```powershell
docker build -f examples/gov-substrate/Dockerfile.controller -t agt-gov-example-controller:local .
docker build -f examples/gov-substrate/Dockerfile.substrate -t agt-gov-example-substrate:local examples/gov-substrate
docker build -f examples/gov-substrate/Dockerfile.worker -t agt-gov-example-worker:local examples/gov-substrate
```

Builds need registry/package access to obtain the base images, Python packages,
and Rust crates. The controller compiles the real native AGT SDK from the current
checkout with its Cargo lockfile. After building, runtime uses only these local
images (`pull_policy: never`), the supplied checkout, and local receivers.
Dependencies are confined to this example's images; AGT core gains none.

## Run the Minimal Example

```powershell
cd examples/gov-substrate
python -B run_example.py --gov-source E:\gov-substrate-v0.7.0
```

The example starts a real isolated scripted worker, delivers an allowed message
to a local SMTP receiver, proves denial by each system with no extra delivery,
rejects grant reuse, checks an unavailable substrate, and verifies worker removal
through AGT's shutdown callback. It then recomputes the substrate audit chain and
checks event/grant/shutdown correlation. Expected: nine `PASS` checks and an
evidence path at `.local/example-proof.json`.

Only the trusted host invokes administrator and Docker inspection commands.
The worker receives only its tool socket and private temporary storage: no
substrate socket, workspace, operator credentials, grant, or Docker socket.

## Failure Behavior

If substrate authorization is unreachable, the bridge returns `decision: deny`,
`reason: substrate_unavailable`, and `outcome: unconfirmed`. It does not invoke
execution, retry automatically, or fall back to an ungoverned executor.

If transport fails during execution, the response is also unconfirmed: an effect
could already have occurred, so callers must not treat it as successful or retry
blindly. An absent substrate during startup fails the bounded readiness check
and cleans up the test deployment. Missing or incorrect shutdown credentials or
worker-ID confirmation produce `terminated: false`, never a success claim.

## Tests

The native contract suite uses the actual native AGT runtime with recording
clients; it is distinct from real execution evidence. From the repository root:

```powershell
$example = (Resolve-Path examples/gov-substrate).Path
docker run --rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges -v "${example}/test_bridge.py:/integration/test_bridge.py:ro" agt-gov-example-controller:local python -B -m unittest -v test_bridge
```

Expected: eleven passing native tests, including effective-argument transformation,
approval binding, both denial paths, evidence correlation, transport failure at
authorization/execution/dispatch, and exact shutdown receipts.

For the minimal example and full real Docker regression:

```powershell
cd examples/gov-substrate
$env:GOV_SUBSTRATE_SOURCE = 'E:\gov-substrate-v0.7.0'
python -B -m pytest -c pytest.ini test_integration.py -v -s --basetemp .local/pytest
```

Expected: two passing tests. The full regression also checks real 120-second
grant expiry, approval pending/rejection, altered requests, revocation, actual
HTTP/file effects, bypass attempts, forced termination, late completion, and
unconfirmed shutdown. It waits for expiry before launching the worker to respect
the real supervisor's separate 120-second lifetime. Generated full evidence is
`.local/proof.json`; credentials, databases and runtime files remain ignored.

## Evidence, Cleanup and Limits

The [historical proof](https://github.com/electricwolfemarshmallowhypertext/ms-agt/blob/390404b254170765705985a3263fd02ee97dcd29/examples/gov-substrate/evidence/proof.json)
records the original 25-check deployment on AGT `ae8c1aed`. It is retained on the
original fork commit, not presented as a run against current main. Reproduce the
current example with the commands above; generated proof records the actual AGT
revision, source hashes, image identities, receiver observations and audit data.

Every run creates unique Compose projects, volumes, synthetic data and random
test-only credentials. `finally` cleanup removes only that deployment and its
tracked worker IDs; no Docker prune or global cleanup is used. If interrupted,
use the exact project and Compose file from `.local/<project>/` with
`docker compose -p <project> -f .local/<project>/compose.json down --volumes --remove-orphans`,
then remove only worker IDs belonging to that project.

The Docker host, controller and substrate/operator service are trusted. Docker
control is available only to the substrate service. Separate credential-free
SMTP and HTTP receivers observe effects; SMTP shares only the substrate network
namespace because v0.7.0's adapter requires loopback. No host ports are published.

This demonstrates one local Docker configuration, not universal confinement,
an independent external witness, or resistance to a compromised host/kernel.
SMTP receipt is not final mailbox delivery; HTTP arrival is not a remote
business outcome. No hosted AI model is used. Maintainer acceptance, including
review of external dependency licensing, remains separate from local validation.
