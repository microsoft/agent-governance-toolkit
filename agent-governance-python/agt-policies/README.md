# agt-policies (5.0.0a1)

This package ships `agt migrate`, the one-way tool that converts an AGT v4
project into an Agent Control Specification (ACS) manifest. It no longer
evaluates policy. Policy evaluation lives in `agent_control_specification`,
which hosts and adapters call directly.

The v4 policy language exists here and nowhere else in the repository. That is
the point of the package: a v4 project has somewhere to go, and the runtime
never has to understand two languages at once.

## Migrating a v4 project

```bash
pip install agt-policies

# Dry run by default: lists every legacy artifact without touching the project.
agt migrate v4-to-v5 .

# Apply it.
agt migrate v4-to-v5 . --write
```

The tool walks the project root, resolves the folder hierarchy that the v4
runtime used to resolve at evaluation time, and writes a flat ACS manifest plus
generated Rego bundles. Each `governance.yaml` it consumes is moved aside to
`.governance.yaml.v4-backup` rather than deleted. Resolution happens once, here,
instead of on every evaluation; the algorithm is specified in
`src/agt/cli/_migrate_resolution/AGT-RESOLUTION-1.0.md`.

`--write-report MIGRATION.md` records what changed.

Migration refuses rather than guesses. Dynamic expressions, host-only settings,
invalid patterns, unsupported fields, and an existing output file all stop the
run with an error naming the construct.

## After migrating

The generated manifest is what the runtime evaluates. Load it through the ACS
SDK:

```python
from agent_control_specification import AgentControl, HostSession

control = AgentControl.from_path("policies/manifest.yaml")
session = HostSession(control, agent_id="mail-agent", session_id="run-1")

result = session.input("summarise the last thread")
if not result.verdict.decision.permits:
    raise RuntimeError(result.verdict.reason)
```

`HostSession` owns one session's snapshots and budget counters over a stateless
runtime, and exposes one method per intervention point. Verdicts are `allow`,
`warn`, `deny`, `escalate`, and `transform`, and `decision.permits` is true for
the three that let the action proceed.

Framework adapters do not need this package. `agent_os.integrations` builds its
own snapshots and calls ACS directly.

## Security invariants

- The migration output is validated with `validate_manifest` before an atomic
  write, so an invalid manifest is never left on disk.
- Regex and glob patterns are validated against OPA's Go RE2 engine, which is
  what evaluates them at runtime, so a pattern that migrates is one the runtime
  can actually run.
- The resolution algorithm is confined to the migration path. No runtime module
  imports it.

## Install (development)

```bash
pip install -e "agent-governance-python/agt-policies[dev]"
pytest agent-governance-python/agt-policies/tests
```
