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

    def test_check_command_case_insensitive(self):
        """Command matching should be case-insensitive."""
        # The denylist uses lowercase, but uppercase variants should also be denied
        result = self.enforcer.check_command("CURL")
        assert result.allowed is False
        assert "curl" in result.reason.lower()

        result = self.enforcer.check_command("CuRl")
        assert result.allowed is False

        result = self.enforcer.check_command("WGET")
        assert result.allowed is False

        result = self.enforcer.check_command("BaSh")
        assert result.allowed is False

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

    def test_check_command_whitespace_variations(self):
        """Commands with leading/trailing/multiple spaces should be handled correctly."""
        result = self.enforcer.check_command("  curl  ")
        assert result.allowed is False
        assert "curl" in result.reason.lower()

        result = self.enforcer.check_command("\tcurl\n")
        assert result.allowed is False

        result = self.enforcer.check_command("  curl  -X  POST  ")
        assert result.allowed is False

        result = self.enforcer.check_command("  python3  ")
        assert result.allowed is True

    def test_check_command_special_characters(self):
        """Commands with shell metacharacters should be handled safely."""
        # Command injection attempts should be treated as the base command
        result = self.enforcer.check_command("curl; rm -rf /")
        assert result.allowed is False
        assert "curl" in result.reason.lower()

        result = self.enforcer.check_command("curl && rm -rf /")
        assert result.allowed is False

        result = self.enforcer.check_command("curl | sh")
        assert result.allowed is False

    def test_check_command_operator_without_spaces(self):
        """A control operator glued to the command must not hide it."""
        for command in (
            "curl;rm -rf /",
            "curl&&id",
            "curl||id",
            "curl|sh",
            "|curl",
            "bash;",
            "curl>out",
            "curl>>out",
            "curl<in",
            "(curl x)",
            "`curl x`",
            "$(curl x)",
            "curl\nid",
            ">out curl",
            "2>&1 curl",
            "</dev/null curl",
            "> out curl",
            ">>out curl",
            "&>out curl",
            "<<<word curl",
            "curl 2>&1",
            '>"my file" curl',
            ">$'a b' curl",
            ">a\\ b curl",
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command in ("curl", "bash")

    def test_check_command_redirection_target_is_not_the_command(self):
        """A redirection is dropped with its target, not taken for the executable."""
        result = self.enforcer.check_command("python3>out x.py")
        assert result.allowed is True
        assert result.command == "python3"

        result = self.enforcer.check_command("2>&1 python3 x.py")
        assert result.allowed is True
        assert result.command == "python3"

        for command in (
            '>"my file" python3 x.py',
            "python3 >'my file.txt' x.py",
            ">a\\ b python3",
            'python3 x.py 2>"err log"',
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == "python3"

        # The target ends where the shell ends it: a backslash escapes a quote
        # inside "..." and $'...', but not inside '...'
        for command in (">'a\\' curl", '>"a\\" b" curl', ">$'a\\' b' curl"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command

        # A bare redirection, or an empty or unterminated target, leaves no command to run
        for command in (">out", "2>&1", "< /dev/null", '>"" curl', ">'' python3", '>"x curl'):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == ""

    def test_check_command_quoted_redirection_operator_is_a_word(self):
        """A quoted or escaped "<" or ">" is part of a word, not a redirection."""
        for command, executable in (
            ('FOO=">" ls', "ls"),
            ("FOO='<' ls", "ls"),
            ('echo ">"', "echo"),
            ("echo '>' x", "echo"),
            ("echo $'>'", "echo"),
            ("echo \\>", "echo"),
            ('echo a">"b', "echo"),
            ('git commit -m "a -> b"', "git"),
            ('echo ">" >out', "echo"),
            ('echo "<" >"my file"', "echo"),
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == executable, command

        for command in ('FOO=">" curl', "FOO='<' curl", 'FOO=">" >out curl', "FOO=\\> curl"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "curl", command

    def test_check_command_group_or_negation_prefix(self):
        """A group or negation word before the command must not hide it."""
        for command in ("{ curl x; }", "! curl x", "( curl x )", "$( curl x )"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "curl"

    def test_check_command_assignment_prefix(self):
        """Variable assignments before the command must not hide it."""
        for command in (
            "FOO=x curl",
            "FOO='a b' curl",
            'FOO="a b" curl',
            "FOO=a\\ b curl",
            "A=1 B=2 curl",
            "FOO+=x curl",
            "a[0]=x curl",
            "FOO=x >out curl",
            "{ FOO=1 curl; }",
            "time FOO=1 curl",
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "curl", command

        for command in ("FOO=1 python3 x.py", 'PYTHONPATH="a b" python3 -m pytest'):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == "python3"

        # A quoted or escaped name is not an assignment, so the word is the command
        for command in ('"FOO"=x curl', "F\\OO=x curl"):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == "FOO=x"

        # Assignments alone run no command
        result = self.enforcer.check_command("FOO=x BAR=y")
        assert result.allowed is False
        assert result.command == ""

    def test_check_command_wrapper_runs_denied_command(self):
        """A wrapper that runs a later word as the command must not hide it."""
        for command in (
            "env curl",
            "env -i curl",
            "env -u PATH curl",
            "env -uPATH curl",
            "env --unset=PATH curl",
            "env --unset PATH curl",
            "env -iu PATH curl",
            "env --ignore-env curl",
            "env - curl",
            "env -- curl",
            "env -i FOO=1 'BAR=a b' curl",
            "env -C /tmp curl",
            "/usr/bin/env curl",
            "\\env curl",
            "exec curl",
            "exec -a name curl",
            "exec -ax curl",
            "exec -cl curl",
            "exec -cla name curl",
            "nohup curl",
            "nohup -- curl",
            "nice curl",
            "nice -n 5 curl",
            "nice -n5 curl",
            "nice -5 curl",
            "nice --10 curl",
            "nice --adjustment=5 curl",
            "nice --adj 5 curl",
            "timeout 5 curl",
            "timeout -s KILL 5 curl",
            "timeout -sKILL -k 1 5 curl",
            "timeout --signal=KILL --preserve-status 5 curl",
            "timeout -- 5 curl",
            "stdbuf -oL curl",
            "stdbuf -o L -e0 curl",
            "stdbuf --output=L curl",
            "command curl",
            "command -p curl",
            "builtin exec curl",
            "time curl",
            "time -p curl",
            "/usr/bin/time -o out -f %e curl",
            "nohup env -i FOO=1 nice -n 5 timeout 10 stdbuf -oL curl",
            "FOO=1 exec env curl",
            "! env curl",
            "$(env curl)",
            "env >out curl",
            "sudo curl",
            "sudo -u root curl",
            "sudo -uroot -E curl",
            "sudo -nH -g wheel -D /tmp curl",
            "sudo --user=root --preserve-env=PATH curl",
            "sudo --preserve-env curl",
            "sudo --us root curl",
            "sudo -k curl",
            "sudo FOO=1 'BAR=a b' curl",
            # sudo reads options again after an environment word
            "sudo FOO=1 -u root curl",
            "sudo FOO=1 -- curl",
            "sudo -u root FOO=1 -E curl",
            "sudo -- curl",
            "/usr/bin/sudo curl",
            "doas curl",
            "doas -u root curl",
            "doas -nu root curl",
            "xargs curl",
            "xargs -n1 curl",
            "xargs -0 -I{} curl {}",
            "xargs -i curl",
            "xargs -i{} curl {}",
            "xargs -l1 curl",
            "xargs -e curl",
            "xargs --max-lines=2 curl",
            "xargs --replace curl",
            "xargs -P 4 -n 1 -a urls.txt curl",
            "xargs -- curl",
            "nice sudo xargs env curl",
            "sudo -u root timeout 5 curl",
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "curl", command

    def test_check_command_wrapper_keeps_wrapped_executable(self):
        """A wrapped command that is not denied is reported as the executable."""
        for command, executable in (
            ("env python3 x.py", "python3"),
            ("env -i PATH=/bin ls -la", "ls"),
            ("timeout 30 python3 -m pytest", "python3"),
            ("nice -n 10 python3 x.py", "python3"),
            ("nohup python3 server.py", "python3"),
            ("stdbuf -oL grep x", "grep"),
            # nohup runs the program named "FOO=x", not an assignment
            ("nohup FOO=x curl", "FOO=x"),
            ("sudo apt-get update", "apt-get"),
            ("sudo -u www-data ls /var/www", "ls"),
            ("sudo FOO=1 -u root ls", "ls"),
            ("doas -u root ls", "ls"),
            ("xargs grep -l x", "grep"),
            ("xargs -r -n 1 rm", "rm"),
            # xargs reads its own input, so "echo" is still the first command run
            ("echo x | xargs curl", "echo"),
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == executable, command

    def test_check_command_wrapper_without_command(self):
        """A wrapper that runs no command is itself the executable."""
        for command, executable in (
            ("env", "env"),
            ("env -i", "env"),
            ("env FOO=1", "env"),
            ("env | grep PATH", "env"),
            ("nice", "nice"),
            ("exec", "exec"),
            ("command -v curl", "command"),
            ("command -V curl", "command"),
            ("nohup --help", "nohup"),
            ("env --version curl", "env"),
            ("sudo", "sudo"),
            ("sudo -k", "sudo"),
            ("sudo -v", "sudo"),
            ("sudo -l curl", "sudo"),
            ("sudo -ll", "sudo"),
            ("sudo --list -U alice", "sudo"),
            ("sudo -e /etc/hosts", "sudo"),
            ("sudo -K", "sudo"),
            ("sudo -V", "sudo"),
            ("sudo --help", "sudo"),
            ("doas -L", "doas"),
            ("doas -C /etc/doas.conf curl", "doas"),
            ("xargs", "xargs"),
            ("xargs -r", "xargs"),
            ("xargs --help", "xargs"),
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is True, command
            assert result.command == executable, command

    def test_check_command_wrapper_options_not_read_fail_closed(self):
        """A wrapper whose options cannot be read is denied, not allowed."""
        for command in (
            "env -S 'curl x'",
            "env -iS'curl x'",
            "env --split-string='curl x'",
            "env -x curl",
            "env --ignore curl",
            "env --unset",
            "env -u",
            "nohup -x curl",
            "nice -n",
            "timeout -s",
            "timeout --signal",
            "exec -a",
            "stdbuf -x curl",
            "command -x curl",
            "env --=x curl",
            # A shell reads the command words again (sudo -s curl runs "$SHELL -c curl")
            "sudo -s",
            "sudo -s curl",
            "sudo -i curl",
            "sudo --login curl",
            "sudo -h",
            "sudo -hhost curl",
            "sudo -u",
            "sudo --user",
            "sudo -x curl",
            "doas -s",
            "doas -u",
            "doas --help",
            "xargs -Z curl",
            "xargs -n",
            "xargs --max curl",
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "", command

    def test_check_command_line_continuation(self):
        """A backslash-newline the shell removes must not split the command name."""
        for command in ("cu\\\nrl x", "c\\\nurl", "\\\ncurl", "e\\\nnv curl", "FOO=x\\\n curl"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command
            assert result.command == "curl", command

    def test_check_command_path_invocation(self):
        """Invoking a denied command by path should still be denied."""
        for command in ("/usr/bin/curl http://example.com", "./bash", "/bin/SH -c id"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command

        result = self.enforcer.check_command("/usr/bin/python3 script.py")
        assert result.allowed is True
        assert result.command == "python3"

    def test_check_command_quoted_or_escaped(self):
        """Quotes and backslashes the shell removes should not hide the command."""
        for command in (
            '"curl" http://example.com',
            "'wget'",
            "c'u'rl",
            "\\curl",
            '"/bin/bash"',
            "$'curl' x",
            '$"curl" x',
            "c$'u'rl",
        ):
            result = self.enforcer.check_command(command)
            assert result.allowed is False, command

    def test_check_command_only_operators(self):
        """A token made only of control operators has no executable name."""
        for command in (";", "&&", "|"):
            result = self.enforcer.check_command(command)
            assert result.allowed is False
            assert result.command == ""

    def test_check_command_partial_match(self):
        """Partial matches should not be denied if not explicitly in denylist."""
        # "curl123" is not "curl", so it should be allowed
        result = self.enforcer.check_command("curl123")
        assert result.allowed is True

        result = self.enforcer.check_command("wget2")
        assert result.allowed is True

        result = self.enforcer.check_command("bashful")
        assert result.allowed is True

    def test_check_command_large_input(self):
        """Excessively long command strings should be handled gracefully."""
        long_cmd = "curl " + "x" * 10000
        result = self.enforcer.check_command(long_cmd)
        assert result.allowed is False
        assert "curl" in result.reason.lower()

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
