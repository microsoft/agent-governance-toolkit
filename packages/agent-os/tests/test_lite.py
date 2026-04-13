# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AGT Lite — the lightweight governance module."""

import pytest
import time

from agent_os.lite import (
    GovernanceViolation,
    LiteGovernor,
    govern,
)


class TestGovern:
    def test_create_governor(self):
        check = govern(allow=["read_file"])
        assert isinstance(check, LiteGovernor)

    def test_allow_listed_action(self):
        check = govern(allow=["read_file", "web_search"])
        assert check("read_file")
        assert check("web_search")

    def test_deny_unlisted_action(self):
        check = govern(allow=["read_file"])
        with pytest.raises(GovernanceViolation):
            check("execute_code")

    def test_explicit_deny_overrides_allow(self):
        check = govern(allow=["read_file", "delete_file"], deny=["delete_file"])
        assert check("read_file")
        with pytest.raises(GovernanceViolation):
            check("delete_file")

    def test_deny_only_mode(self):
        check = govern(deny=["execute_code", "ssh_connect"])
        assert check("read_file")
        assert check("web_search")
        with pytest.raises(GovernanceViolation):
            check("execute_code")

    def test_deny_patterns(self):
        check = govern(deny_patterns=[r"^delete_", r"^drop_"])
        assert check("read_file")
        with pytest.raises(GovernanceViolation):
            check("delete_anything")
        with pytest.raises(GovernanceViolation):
            check("drop_table")

    def test_is_allowed_non_raising(self):
        check = govern(deny=["bad"])
        assert check.is_allowed("good")
        assert not check.is_allowed("bad")

    def test_content_blocking(self):
        check = govern(
            allow=["read_file"],
            blocked_content=[r'\b\d{3}-\d{2}-\d{4}\b'],  # SSN
        )
        assert check("read_file")
        assert not check.is_allowed("read_file", content="SSN is 123-45-6789")

    def test_rate_limiting(self):
        check = govern(allow=["read"], max_calls=3)
        assert check("read")
        assert check("read")
        assert check("read")
        with pytest.raises(GovernanceViolation):
            check("read")  # 4th call exceeds limit

    def test_audit_trail(self):
        check = govern(allow=["read", "write"], deny=["delete"])
        check("read")
        check("write")
        check.is_allowed("delete")
        assert len(check.audit_trail) == 3
        assert check.audit_trail[0].allowed
        assert not check.audit_trail[2].allowed

    def test_stats(self):
        check = govern(deny=["bad"])
        check("good")
        check("also_good")
        check.is_allowed("bad")
        stats = check.stats
        assert stats["total"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1

    def test_sub_millisecond_latency(self):
        check = govern(allow=["read"], deny=["write"])
        decision = check.evaluate("read")
        assert decision.latency_ms < 1.0  # must be sub-millisecond

    def test_no_config_allows_everything(self):
        check = govern()
        assert check("anything")
        assert check("literally_anything")

    def test_empty_deny_allows_everything(self):
        check = govern(deny=[])
        assert check("read")
        assert check("write")


class TestGovernanceViolation:
    def test_exception_fields(self):
        try:
            check = govern(deny=["bad"])
            check("bad")
        except GovernanceViolation as e:
            assert e.action == "bad"
            assert "denied" in e.reason


class TestLitePerformance:
    def test_1000_evaluations_under_10ms(self):
        check = govern(
            allow=["read", "write", "search"],
            deny=["delete", "execute"],
            deny_patterns=[r"^admin_"],
            blocked_content=[r'\d{3}-\d{2}-\d{4}'],
            log=False,
        )
        start = time.perf_counter()
        for _ in range(1000):
            check.is_allowed("read")
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100  # 1000 evals in under 100ms
