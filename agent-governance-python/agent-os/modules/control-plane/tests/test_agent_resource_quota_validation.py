# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for AgentResourceQuota limit validation.

ResourceQuotaManager.can_execute compares usage against each limit, so a
negative limit is met by any usage and would deny every operation while
reading as a quota. 0 is a meaningful setting - permit nothing - so only
negative values are rejected.
"""

import pytest
from agent_control_plane.lifecycle import AgentResourceQuota, ResourceQuotaManager

REQUIRED_LIMITS = (
    "memory_mb",
    "cpu_percent",
    "max_concurrent_operations",
    "max_operations_per_minute",
)
OPTIONAL_LIMITS = ("network_bandwidth_mbps", "storage_mb")
ALL_LIMITS = REQUIRED_LIMITS + OPTIONAL_LIMITS


class TestAgentResourceQuotaValidation:
    """Construction-time validation of the quota limits."""

    def test_defaults_are_accepted(self):
        quota = AgentResourceQuota()
        assert quota.memory_mb == 512
        assert quota.cpu_percent == 25.0
        assert quota.max_concurrent_operations == 10
        assert quota.max_operations_per_minute == 100

    @pytest.mark.parametrize("name", ALL_LIMITS)
    def test_zero_is_accepted_as_permit_nothing(self, name):
        assert getattr(AgentResourceQuota(**{name: 0}), name) == 0

    @pytest.mark.parametrize("name", ALL_LIMITS)
    def test_positive_limits_are_accepted(self, name):
        assert getattr(AgentResourceQuota(**{name: 7}), name) == 7

    @pytest.mark.parametrize("name", OPTIONAL_LIMITS)
    def test_none_is_accepted_on_the_optional_limits(self, name):
        assert getattr(AgentResourceQuota(**{name: None}), name) is None

    @pytest.mark.parametrize("name", ALL_LIMITS)
    @pytest.mark.parametrize("value", [-1, -100])
    def test_negative_limits_are_rejected(self, name, value):
        with pytest.raises(ValueError, match=name):
            AgentResourceQuota(**{name: value})


class TestZeroQuotaStillDenies:
    """A zero quota denies, which is why 0 stays legal."""

    def _manager(self, quota):
        manager = ResourceQuotaManager()
        manager.set_quota("agent-1", quota)
        manager.update_resource_usage("agent-1", memory_mb=0.0, cpu_percent=0.0)
        return manager

    def test_default_quota_permits_execution(self):
        assert self._manager(AgentResourceQuota()).can_execute("agent-1") is True

    def test_zero_concurrent_operations_denies_execution(self):
        manager = self._manager(AgentResourceQuota(max_concurrent_operations=0))
        assert manager.can_execute("agent-1") is False

    def test_zero_operations_per_minute_denies_execution(self):
        manager = self._manager(AgentResourceQuota(max_operations_per_minute=0))
        assert manager.can_execute("agent-1") is False
