# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for ResourceQuota limit validation.

Each limit is compared with ``>=`` against current usage, so a negative
limit is never met and would deny every request while reading as a
quota. 0 is a meaningful setting here - permit nothing - so only
negative values are rejected.
"""

import unittest

from agent_control_plane import AgentControlPlane
from agent_control_plane.agent_kernel import ActionType, PermissionLevel
from agent_control_plane.policy_engine import ResourceQuota

LIMIT_FIELDS = (
    "max_requests_per_minute",
    "max_requests_per_hour",
    "max_execution_time_seconds",
    "max_concurrent_executions",
)


class TestResourceQuotaValidation(unittest.TestCase):
    """Construction-time validation of the quota limits."""

    def test_defaults_are_accepted(self):
        quota = ResourceQuota(agent_id="a")
        self.assertEqual(quota.max_requests_per_minute, 60)
        self.assertEqual(quota.max_requests_per_hour, 1000)
        self.assertEqual(quota.max_concurrent_executions, 5)

    def test_zero_is_accepted_as_permit_nothing(self):
        for name in LIMIT_FIELDS:
            with self.subTest(field=name):
                quota = ResourceQuota(agent_id="a", **{name: 0})
                self.assertEqual(getattr(quota, name), 0)

    def test_positive_limits_are_accepted(self):
        for name in LIMIT_FIELDS:
            with self.subTest(field=name):
                quota = ResourceQuota(agent_id="a", **{name: 7})
                self.assertEqual(getattr(quota, name), 7)

    def test_negative_limits_are_rejected(self):
        for name in LIMIT_FIELDS:
            for value in (-1, -100):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError) as caught:
                        ResourceQuota(agent_id="a", **{name: value})
                    self.assertIn(name, str(caught.exception))

    def test_usage_counters_are_not_validated(self):
        # Only the limits carry the invariant; the usage fields are
        # bookkeeping the engine owns.
        quota = ResourceQuota(agent_id="a", requests_this_minute=3)
        self.assertEqual(quota.requests_this_minute, 3)


class TestZeroQuotaStillDenies(unittest.TestCase):
    """A zero request quota denies, which is why 0 stays legal."""

    def test_zero_requests_per_minute_denies_the_first_request(self):
        plane = AgentControlPlane()
        quota = ResourceQuota(
            agent_id="zero-agent",
            max_requests_per_minute=0,
            allowed_action_types=[ActionType.FILE_READ],
        )
        context = plane.create_agent(
            "zero-agent",
            {ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            quota,
        )
        result = plane.execute_action(
            context, ActionType.FILE_READ, {"path": "/data/file1.txt"}
        )
        self.assertFalse(result["success"])

    def test_positive_quota_permits_the_first_request(self):
        plane = AgentControlPlane()
        quota = ResourceQuota(
            agent_id="one-agent",
            max_requests_per_minute=1,
            allowed_action_types=[ActionType.FILE_READ],
        )
        context = plane.create_agent(
            "one-agent",
            {ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            quota,
        )
        result = plane.execute_action(
            context, ActionType.FILE_READ, {"path": "/data/file1.txt"}
        )
        self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
