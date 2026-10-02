# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Policy condition-DSL string operators: contains / startswith / endswith.

Demonstrates the three string operators plus their fail-closed/fail-open
semantics on bad data. See README.md in this directory for the narrative
explanation of why these operators matter.

Each check below asserts its expected value rather than just printing it:
on a pre-#3924 install these operators silently evaluate to False with no
warning, so a print-only demo would look identical whether the fix is
present or not. An assertion failure here means the installed
agent-governance-toolkit-core does not yet include #3924 — see the
Prerequisites section in README.md.
"""

from agentmesh.governance.policy import PolicyRule


def check(rule: PolicyRule, context: dict, expected: bool, label: str) -> None:
    actual = rule.evaluate(context)
    print(f"{label}: {actual}")
    assert actual is expected, (
        f"{label}: expected {expected}, got {actual} — is agentmesh missing #3924's "
        "contains/startswith/endswith fix? See README.md Prerequisites."
    )


# contains — deny path traversal anywhere in the string
path_traversal = PolicyRule(
    name="deny-path-traversal",
    condition="action.path contains '..'",
    action="deny",
)
check(path_traversal, {"action": {"path": "../../etc/passwd"}}, True, "path traversal denied")
check(path_traversal, {"action": {"path": "/etc/passwd"}}, False, "clean path allowed")

# startswith — deny an entire family of tools by name prefix
delete_tools = PolicyRule(
    name="deny-delete-tools",
    condition="action.tool startswith 'delete_'",
    action="deny",
)
check(delete_tools, {"action": {"tool": "delete_user"}}, True, "delete_user denied")
check(delete_tools, {"action": {"tool": "read_user"}}, False, "read_user allowed")

# endswith — deny access to a class of resources by suffix
key_files = PolicyRule(
    name="deny-key-files",
    condition="resource.name endswith '.pem'",
    action="deny",
)
check(key_files, {"resource": {"name": "server.pem"}}, True, "server.pem denied")
check(key_files, {"resource": {"name": "server.pem.bak"}}, False, "server.pem.bak allowed")

# Fail-closed by design: a non-string or missing field makes a `deny` rule
# using these operators match (fail closed), and makes an `allow` rule using
# them *not* match (fail open here would grant access on bad data).
check(path_traversal, {"action": {"path": 123}}, True, "non-string field: deny fires")
check(path_traversal, {"action": {}}, True, "missing field: deny fires")

allow_safe = PolicyRule(
    name="allow-safe-path", condition="action.path contains 'safe'", action="allow"
)
check(allow_safe, {"action": {"path": 123}}, False, "non-string field: allow does not fire")

print("\nAll assertions passed — contains/startswith/endswith and their "
      "fail-closed/fail-open semantics are working as documented.")
