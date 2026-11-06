# SPDX-License-Identifier: MIT
"""Conformance of native ACS host mediation around committed tool effects.

The SDK enforces pre- and post-tool decisions at different points in time.
Post-tool denial prevents returning a result; it cannot undo a prior durable
external effect. The host is responsible for routing all tool executions
through the guard. These tests do not assert complete mediation.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    EnforcementMode,
)


MANIFEST = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: native-effect-boundary-test
policies:
  write_policy:
    type: custom
    adapter: write_test_policy
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: write_policy
  post_tool_call:
    policy_target: $.tool_result
    policy_target_kind: tool_result
    tool_name_from: $.tool_call.name
    policy:
      id: write_policy
tools:
  write_record:
    type: Tool
    id: write_record
    clearance: internal
"""


class WritePolicy:
    def __init__(self) -> None:
        self.pre_calls = 0
        self.post_calls = 0

    def evaluate(self, invocation):
        target = invocation["input"]["policy_target"]["value"]
        if "committed" in target:
            self.post_calls += 1
            return {"decision": "deny" if target["reject_result"] else "allow"}
        self.pre_calls += 1
        allow = target.get("resource", "").startswith("/allowed/")
        return {"decision": "allow" if allow else "deny"}


class NativeToolEffectBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="acs effect # ")
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / "effects.sqlite"
        with closing(sqlite3.connect(self.database)) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE effects (id INTEGER PRIMARY KEY, resource TEXT NOT NULL)"
                )
        self.policy = WritePolicy()
        self.control = AgentControl.from_native(MANIFEST, None, self.policy)
        self.executor_calls = 0

    def committed_resources(self) -> list[str]:
        # A separate read-only database connection observes the committed state.
        with closing(
            sqlite3.connect(self.database.resolve().as_uri() + "?mode=ro", uri=True)
        ) as connection:
            return [
                resource
                for (resource,) in connection.execute(
                    "SELECT resource FROM effects ORDER BY id"
                )
            ]

    async def execute(self, arguments):
        self.executor_calls += 1
        with closing(sqlite3.connect(self.database)) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO effects(resource) VALUES (?)",
                    (arguments["resource"],),
                )
        return {
            "committed": True,
            "reject_result": arguments["reject_result"],
        }

    def invoke(self, resource: str, *, reject_result: bool = False):
        return asyncio.run(
            self.control.run_tool(
                "write_record",
                {"resource": resource, "reject_result": reject_result},
                self.execute,
                tool_call_id="write-1",
                mode=EnforcementMode.ENFORCE,
            )
        )

    def test_pre_tool_deny_prevents_executor_and_commit(self):
        with self.assertRaises(AgentControlBlocked):
            self.invoke("/restricted/report")
        self.assertEqual(self.executor_calls, 0)
        self.assertEqual(self.policy.pre_calls, 1)
        self.assertEqual(self.policy.post_calls, 0)
        self.assertEqual(self.committed_resources(), [])

    def test_post_tool_deny_does_not_rollback_prior_commit(self):
        with self.assertRaises(AgentControlBlocked):
            self.invoke("/allowed/report", reject_result=True)
        self.assertEqual(self.executor_calls, 1)
        self.assertEqual(self.policy.pre_calls, 1)
        self.assertEqual(self.policy.post_calls, 1)
        self.assertEqual(self.committed_resources(), ["/allowed/report"])

    def test_pre_and_post_allow_commit_exactly_once(self):
        result = self.invoke("/allowed/report")
        self.assertTrue(result.value["committed"])
        self.assertEqual(self.executor_calls, 1)
        self.assertEqual(self.policy.pre_calls, 1)
        self.assertEqual(self.policy.post_calls, 1)
        self.assertEqual(self.committed_resources(), ["/allowed/report"])

    def test_direct_executor_bypass_is_outside_sdk_guard(self):
        asyncio.run(
            self.execute({"resource": "/restricted/bypass", "reject_result": False})
        )
        self.assertEqual(self.executor_calls, 1)
        self.assertEqual((self.policy.pre_calls, self.policy.post_calls), (0, 0))
        self.assertEqual(self.committed_resources(), ["/restricted/bypass"])
