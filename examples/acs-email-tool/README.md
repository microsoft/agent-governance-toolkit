# ACS email-tool enforcement

This framework-neutral example shows the canonical AGT 5 policy path:

```text
Host -> SnapshotBuilder -> AgtRuntime -> ACS verdict -> host enforcement
```

The host evaluates `send_email` before execution. The custom policy produces
three ACS outcomes:

| Input | Verdict | Host behavior |
|---|---|---|
| Internal recipient | `allow` | Execute unchanged |
| Body containing `TRACK-*` | `transform` | Redact the token, then execute |
| Recipient under `example.net` | `deny` | Do not execute |

The policy is intentionally local and deterministic so the example needs no
model, network call, secret, or OPA installation.

## Files

```text
acs-email-tool/
  email_policy.py       Host-provided custom ACS policy dispatcher
  manifest.yaml         ACS intervention-point and policy configuration
  run.py                Snapshot construction and verdict enforcement
  test_email_tool.py    Policy unit tests and optional native runtime test
```

## Setup

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
pip install ./policy-engine/sdk/python
pip install -e "./agent-governance-python/agt-policies[dev]"
```

`agt-policies` is the AGT host package. It builds snapshots, calls the vendored
ACS runtime, and maps the returned verdict into an `EvaluationResult`.

## Run

```bash
python examples/acs-email-tool/run.py
```

Expected output:

```text
[allow] decision=allow sent=True body=Your case is ready.
[transform] decision=transform sent=True body=Your case is ready. Tracking token: [REDACTED]
[deny] decision=deny executed=False reason=external_recipient_blocked
```

The host owns the side effect. ACS only returns the decision and transformed
target, so the denied case never calls `send_email`.

## Test

```bash
pytest examples/acs-email-tool/test_email_tool.py
```

The dispatcher tests run without the native SDK. The end-to-end test runs when
`agent-control-specification` and `agt-policies` are installed.

## Cleanup

```bash
deactivate
rm -rf .venv
```

