# Policy Condition-DSL String Operators

`PolicyRule`'s condition DSL supports `==`, `!=`, `in [...]`, numeric
comparisons, and bare boolean checks, plus `contains`/`startswith`/
`endswith` for substring and prefix/suffix matching on string fields.

Before those three operators existed, a condition like
`action.tool startswith 'delete_'` fell through every branch in
`_eval_expression` and silently evaluated to `False` — a no-match, not an
error. For a `deny` rule, that meant the rule **never fired and never
warned**: a policy author could write a rule that looked correct, ship it,
and have it silently do nothing.

This example shows the three operators working correctly, and the
fail-closed/fail-open semantics they follow on bad data.

## Prerequisites

`PolicyRule` is a standalone, importable class (the import path stays
`agentmesh.governance.policy`; only the distribution name changed under
the package consolidation — see
[MIGRATION.md](../../docs/package-consolidation/MIGRATION.md)), but the
`contains`/`startswith`/`endswith` operators shown here landed in #3924
(merged 2026-09-15) and are **not in any released version of
`agent-governance-toolkit-core` yet** — the latest release on PyPI as of
this writing is 5.0.0 (2026-08-03). `pip install agent-governance-toolkit-core`
today gets you a version that silently prints `False` for every check below
(the exact bug this example demonstrates was fixed) — check
[the PyPI release history](https://pypi.org/project/agent-governance-toolkit-core/#history)
for a release dated after 2026-09-15, or run from a checkout in the
meantime:

```bash
pip install 'pydantic[email]' pyyaml cryptography httpx python-dateutil
PYTHONPATH=agent-governance-python/agent-mesh/src:agent-governance-python/agent-hypervisor/src:agent-governance-python/agt-policies/src \
  python examples/policy-condition-operators/string_operators.py
```

## How to Run

Once a release with #3924 is available:

```bash
pip install agent-governance-toolkit-core
python examples/policy-condition-operators/string_operators.py
```

## Usage

```python
from agentmesh.governance.policy import PolicyRule

# contains — deny path traversal anywhere in the string
path_traversal = PolicyRule(
    name="deny-path-traversal",
    condition="action.path contains '..'",
    action="deny",
)
print(path_traversal.evaluate({"action": {"path": "../../etc/passwd"}}))  # True
print(path_traversal.evaluate({"action": {"path": "/etc/passwd"}}))       # False

# startswith — deny an entire family of tools by name prefix
delete_tools = PolicyRule(
    name="deny-delete-tools",
    condition="action.tool startswith 'delete_'",
    action="deny",
)
print(delete_tools.evaluate({"action": {"tool": "delete_user"}}))  # True
print(delete_tools.evaluate({"action": {"tool": "read_user"}}))    # False

# endswith — deny access to a class of resources by suffix
key_files = PolicyRule(
    name="deny-key-files",
    condition="resource.name endswith '.pem'",
    action="deny",
)
print(key_files.evaluate({"resource": {"name": "server.pem"}}))      # True
print(key_files.evaluate({"resource": {"name": "server.pem.bak"}}))  # False
```

**Fail-closed by design:** a non-string or missing field makes a `deny`
rule using these operators match (fail closed), and makes an `allow` rule
using them *not* match (fail open here would grant access on bad data).
Continuing from the `path_traversal` rule defined in the block above:

```python
print(path_traversal.evaluate({"action": {"path": 123}}))  # True  — deny fires
print(path_traversal.evaluate({"action": {}}))              # True  — deny fires

allow_safe = PolicyRule(
    name="allow-safe-path", condition="action.path contains 'safe'", action="allow"
)
print(allow_safe.evaluate({"action": {"path": 123}}))  # False — allow does not fire
```

**Scope:** this covers the three string operators only. `and`/`or`
combination, numeric comparisons, and `in [...]` membership are pre-existing
DSL features and aren't repeated here.
