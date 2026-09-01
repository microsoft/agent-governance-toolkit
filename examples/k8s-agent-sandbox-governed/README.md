# kubernetes-sigs/agent-sandbox + Agent Governance Toolkit

Govern the commands an agent sends to a [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
pod, before they are ever dispatched.

## Prior art

This example integrates with, and is not affiliated with, [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox),
a CNCF SIG project providing Kubernetes-native execution isolation (pod
sandboxing, per-template `NetworkPolicy`) for agent workloads. All CRDs,
the controller, and the sandbox-router referenced here come from that
project's own releases — this example only adds the client-side
governance wrapper around its Python SDK.

## Architecture

```
Agent driving script (run_agent.py)
     |
     v
_classify_command()   -- pre-classifies the command + local script body
     |                    into a discrete action.type (policy DSL only
     |                    supports equality/membership, not substring match)
     v
govern(...)            -- evaluates policy.yaml against {"type": ..., "command": ...}
     |-- allow  --> create_sandbox() -> files.write() -> sandbox.commands.run(...)
     '-- deny   --> GovernanceDenied raised, no sandbox pod ever claimed
```

A denied command never reaches (or even claims) a sandbox pod — this is
defense-in-depth *before* isolation, not a substitute for it, and it avoids
wasting a warm-pool claim on a request that governance would reject anyway.

## Quick Start

### 1. Set up an agent-sandbox cluster

Follow the [agent-sandbox quickstart](https://github.com/kubernetes-sigs/agent-sandbox/blob/main/examples/quickstart/README.md)
to get a `python-warmpool` running in the `agent-sandbox-demo`
namespace on any cluster (kind by default).

### 2. Install dependencies

```bash
cd examples/k8s-agent-sandbox-governed
pip install -r requirements.txt
```

`requirements.txt` has exactly two dependencies: `agent-governance-toolkit[full]`
(this repo — provides `govern()`/`GovernanceDenied`) and `k8s-agent-sandbox`
(the upstream Python SDK for talking to agent-sandbox's sandbox-router). No
other third-party packages are needed.

### 3. Run a benign script — allowed

```bash
python run_agent.py hello_world.py --warmpool python-warmpool --namespace agent-sandbox-demo
```

```
Hello from a governed sandbox pod
```

### 4. Run a destructive script — denied before dispatch

```bash
python run_agent.py destructive.sh --interpreter bash \
  --warmpool python-warmpool --namespace agent-sandbox-demo
```

```
Command blocked by governance policy: Action denied by policy rule 'block-destructive-commands':
Commands classified as destructive (rm -rf, mkfs, dd, disk wipes, fork bombs, pipe-to-shell installers) are blocked before dispatch.
```

Exit code is `1`, and `rm -rf /` never runs inside the pod — compare this to
relying on the pod's own isolation to contain it after the fact.

## Integration pattern

```python
from agentmesh.governance import govern, GovernanceDenied

def _dispatch(action):
    # Sandbox is claimed here, inside the governed call, so a denied
    # action never costs a pod claim.
    sandbox = client.create_sandbox(warmpool="...", namespace="...")
    sandbox.files.write(remote_name, script_bytes)
    return sandbox.commands.run(action["command"], timeout=60)

governed_run = govern(
    _dispatch,
    policy="policy.yaml",
    agent_id="run_agent:agent-sandbox-demo",
)

try:
    result = governed_run(action={"type": action_type, "command": command})
except GovernanceDenied as e:
    print(f"blocked: {e}")
```

`policy.yaml` owns the allow/deny rules and audit trail; `run_agent.py` owns
pre-classifying free-text commands/scripts into the discrete `action.type`
values the policy conditions match against.

## Cleanup

`run_agent.py` already terminates the individual sandbox it creates
(`sandbox.terminate()` in a `finally` block) after each run, so nothing is
left behind per-invocation. To tear down the shared resources this example
relies on:

```bash
kubectl delete sandboxwarmpool python-warmpool -n agent-sandbox-demo
kubectl delete sandboxtemplate python-sandbox-template -n agent-sandbox-demo
```

If you created a dedicated cluster just for this example, follow
[Step 10: Cleanup](https://github.com/kubernetes-sigs/agent-sandbox/blob/main/examples/quickstart/README.md#step-10-cleanup)
in the agent-sandbox quickstart (e.g. `kind delete cluster ...`) to remove
it entirely.

## Notes

- Tested against a local [EKS Anywhere](https://anywhere.eks.amazonaws.com/) (Docker provider) cluster; the same pattern works unmodified against `kind`, `minikube`, or any real cluster running agent-sandbox.
- `policy.yaml`'s rules (`block-destructive-commands`, `block-credential-exfil`, `allow-shell-exec`) are illustrative — extend `_classify_command()` and the policy's `rules` list for your own risk model. `default_action: deny` means any `action.type` not explicitly allowed is blocked, including future classifications `_classify_command()` doesn't yet return.
- `run_agent.py` uses `SandboxLocalTunnelConnectionConfig`, which assumes the sandbox-router is reachable via a local tunnel (e.g. `kubectl port-forward`, or a `kind`/`minikube` cluster on localhost). If you're targeting a remote cluster, swap in the connection config `k8s-agent-sandbox` provides for direct/in-cluster access instead.

## Known Limitations

- `_classify_command()`'s regex patterns are a minimal illustrative filter, not a production-grade detector. Matching is case-insensitive and flag-order-tolerant for the patterns above, but the pattern set itself is still narrow and can be bypassed, e.g. exfiltration via a command/tool not in `_CREDENTIAL_EXFIL_PATTERNS` (piping to something other than `curl`/`wget`/`nc`), or any destructive/exfil technique not covered by the listed patterns at all. Do not deploy this policy verbatim as a production risk model — treat it as a starting point.
- Classification happens once, from the local copy of the script; it does not account for scripts that download or generate additional code at runtime inside the sandbox.
- `k8s-agent-sandbox`'s `commands.run()` only accepts a single shell command string, not an argv list, so `run_agent.py` shell-quotes `script_args` with `shlex.join()` before sending. This prevents metacharacters in `script_args` from being interpreted as additional shell syntax by whatever shell the sandbox pod uses to execute the command, but it doesn't change what the script itself does once running — a malicious script body is still subject only to `_classify_command()`'s pattern matching above.

## Disclaimer

This example's `README.md`, `policy.yaml`, and `run_agent.py` were drafted with Claude Code, then reviewed and manually verified by the author against a real cluster (see Testing in the PR description). No part of this example was generated and submitted without human review.
