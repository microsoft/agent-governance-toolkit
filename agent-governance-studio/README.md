# AGT Studio

AGT Studio is the canonical package for the Agent Governance Toolkit's unified
UI. Its Python distribution is `agent-governance-studio` (import
`agent_governance_studio`); its frontend is
`@microsoft/agent-governance-studio`. This draft layer adds the loopback-only,
save-disabled `agt serve` backend above the unmerged scaffold #4170.
It is **not approved for merge** until the scaffold and Studio/Engine API/security
reviews are complete. See the [sidecar usage and review gates](https://github.com/microsoft/agent-governance-toolkit/blob/ricky-g-studio-sidecar-implementation/docs/studio/sidecar.md),
[Studio execution tracker](https://github.com/microsoft/agent-governance-toolkit/issues/2729)
and [ADR 0028](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/adr/0028-agt-studio-unified-ui.md)
for the agreed scope.

From the repository root, with the Python build, pytest, and Ruff tools
installed and Node.js 20.19+ (or 22.12+):

```sh
python -m build agent-governance-studio
python -m pytest agent-governance-studio/tests -q
ruff check agent-governance-studio/src agent-governance-studio/tests --select E,F,W --ignore E501

npm ci --ignore-scripts --prefix agent-governance-studio/web
npm run lint --prefix agent-governance-studio/web
npm test --prefix agent-governance-studio/web
npm run build --prefix agent-governance-studio/web
```

The installed wheel registers a lazy Click plugin through the compliance CLI's
`agt.commands` group, without replacing the `agt` executable:

```text
agt serve --help
agt serve
agt serve --host 127.0.0.1 --port 8080 --policy-dir <read-only-directory>
```

Startup verifies the real core/compliance/native ACS/OPA backend, snapshots the
bounded policy inventory, binds the socket, then reports readiness. Only literal
`127.0.0.1` is accepted. Without a policy root the inventory is intentionally
empty; `AGT_STUDIO_POLICY_DIR` is used only when `--policy-dir` is absent.
Legacy adapter policy/save environment variables cannot select a root or enable saving.

The canonical adapter runs in owned, killable request processes, retaining its
12 operation identities and 11-operation read-only projection. JSON POST callers
must send the listener's exact `Origin` and `X-AGT-Studio-Request: 1`.
Saving is always forbidden. Exact Host/Origin, proxy/fetch-site gates, finite
resource budgets and privacy headers apply server-side. These controls do not
authenticate a hostile same-user process.

The [usage page](https://github.com/microsoft/agent-governance-toolkit/blob/ricky-g-studio-sidecar-implementation/docs/studio/sidecar.md)
documents the reproducible wheel install (including the unpublished native ACS
dependency), finite defaults, shutdown behavior and proposed transport/error
contract. The Python tests require real installed wheels, OPA, Rust for a
deliberately failing descendant-process fixture, and
`AGT_STUDIO_TEST_WHEELHOUSE` pointing to the production wheelhouse.
SPA, `agt ui`, token provisioning, remote mode, policy authoring, events and
runtime-control routes remain deferred. The scaffold's frontend is unchanged.
