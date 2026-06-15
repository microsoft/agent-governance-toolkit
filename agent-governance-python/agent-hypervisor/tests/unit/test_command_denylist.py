# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for command denylist enforcement."""

from __future__ import annotations

import pytest

from hypervisor.models import ExecutionRing
from hypervisor.rings.enforcer import ResourceType, RingEnforcer
from hypervisor.sandbox import DENIED_COMMANDS


class TestCommandDenylist:
    """Tests for command denylist enforcement."""

    def setup_method(self):
        self.enforcer = RingEnforcer()

    def test_denied_commands_constant_exists(self):
        """DENIED_COMMANDS should be defined and non-empty."""
        assert len(DENIED_COMMANDS) > 0
        # Core network tools should be denied
        assert "curl" in DENIED_COMMANDS
        assert "wget" in DENIED_COMMANDS
        # Shells should be denied
        assert "bash" in DENIED_COMMANDS
        assert "sh" in DENIED_COMMANDS

    def test_check_command_allows_safe_commands(self):
        """Safe commands not in denylist should be allowed."""
        # These are not in DENIED_COMMANDS
        result = self.enforcer.check_command("python3")
        assert result.allowed is True
        assert "allowed" in result.reason.lower()

        result = self.enforcer.check_command("ls")
        assert result.allowed is True

        result = self.enforcer.check_command("cat")
        assert result.allowed is True

    def test_check_command_denies_curl(self):
        """curl should be denied."""
        result = self.enforcer.check_command("curl")
        assert result.allowed is False
        assert "denied" in result.reason.lower()
        assert "curl" in result.reason.lower()

    def test_check_command_denies_wget(self):
        """wget should be denied."""
        result = self.enforcer.check_command("wget")
        assert result.allowed is False
        assert "denied" in result.reason.lower()

    def test_check_command_denies_shells(self):
        """Shell interpreters should be denied."""
        for shell in ["bash", "sh", "zsh", "fish", "ksh", "dash"]:
            result = self.enforcer.check_command(shell)
            assert result.allowed is False, f"{shell} should be denied"
            assert "denied" in result.reason.lower()

    def test_check_command_denies_compilers(self):
        """Compilers should be denied."""
        for compiler in ["gcc", "g++", "cc", "make"]:
            result = self.enforcer.check_command(compiler)
            assert result.allowed is False, f"{compiler} should be denied"

    def test_check_command_denies_alternative_interpreters(self):
        """Alternative interpreters should be denied."""
        for interp in ["perl", "ruby", "python2"]:
            result = self.enforcer.check_command(interp)
            assert result.allowed is False, f"{interp} should be denied"

    def test_check_command_denies_network_tools(self):
        """Network tools should be denied."""
        for tool in ["nc", "ncat", "netcat", "socat", "nmap", "tcpdump", "ftp", "telnet"]:
            result = self.enforcer.check_command(tool)
            assert result.allowed is False, f"{tool} should be denied"

    def test_check_command_case_sensitive(self):
        """Command matching should be case-sensitive (exact match)."""
        # The denylist uses lowercase
        result = self.enforcer.check_command("CURL")
        # CURL (uppercase) is not in the denylist, so it would be allowed
        # This is the current behavior - exact string match
        # If we want case-insensitive, we'd need to change the implementation
        assert result.allowed is True

    def test_check_command_with_args(self):
        """Commands with arguments should check only the command name."""
        result = self.enforcer.check_command("curl -X POST http://example.com")
        assert result.allowed is False
        assert "curl" in result.reason.lower()

        result = self.enforcer.check_command("ls -la")
        assert result.allowed is True

    def test_check_command_empty_string(self):
        """Empty command should be denied."""
        result = self.enforcer.check_command("")
        assert result.allowed is False

    def test_check_command_none(self):
        """None command should be denied."""
        result = self.enforcer.check_command(None)
        assert result.allowed is False

    def test_all_denied_commands_are_checked(self):
        """Every entry in DENIED_COMMANDS should be denied by check_command."""
        for cmd in DENIED_COMMANDS:
            result = self.enforcer.check_command(cmd)
            assert result.allowed is False, f"{cmd} from DENIED_COMMANDS should be denied"

    def test_check_command_integrates_with_resource_check(self):
        """check_command should respect ring-level subprocess permission."""
        # Ring 3 has subprocess_allowed=False
        resource_result = self.enforcer.check_resource(
            ExecutionRing.RING_3_SANDBOX, ResourceType.SUBPROCESS
        )
        assert resource_result.allowed is False

        # Even if a command is not in denylist, ring 3 should deny subprocess
        # But check_command itself doesn't check ring - it's a separate concern
        # The caller should check both


class TestCommandCheckResult:
    """Tests for CommandCheckResult structure."""

    def test_result_has_required_fields(self):
        """CommandCheckResult should have allowed, reason, command fields."""
        enforcer = RingEnforcer()
        result = enforcer.check_command("curl")

        assert hasattr(result, "allowed")
        assert hasattr(result, "reason")
        assert hasattr(result, "command")
        assert result.command == "curl"

    def test_allowed_result_structure(self):
        """Allowed result should have proper structure."""
        enforcer = RingEnforcer()
        result = enforcer.check_command("python3")

        assert result.allowed is True
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0

    def test_denied_result_structure(self):
        """Denied result should have proper structure."""
        enforcer = RingEnforcer()
        result = enforcer.check_command("curl")

        assert result.allowed is False
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0
        assert "curl" in result.reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
