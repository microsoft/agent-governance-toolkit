# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ring Enforcer — resource-constrained ring-based access control.

Maps execution rings to concrete resource constraints (network, filesystem,
subprocess) and enforces both ring-level access and resource-level restrictions.

Also provides command denylist enforcement for subprocess execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from hypervisor.constants import RING_1_ENFORCER_THRESHOLD
from hypervisor.models import ActionDescriptor, ExecutionRing
from hypervisor.sandbox import DENIED_COMMANDS


class ResourceType(str, Enum):
    """Types of resources that rings constrain."""

    NETWORK = "network"
    FILESYSTEM = "filesystem"
    SUBPROCESS = "subprocess"
    TOOL_EXECUTION = "tool_execution"


@dataclass
class ResourceConstraints:
    """Resource constraints for an execution ring.

    Defines what an agent at a given ring level is allowed to do.
    """

    network_allowed: bool = False
    network_allowlist: list[str] = field(default_factory=list)
    filesystem_writable: bool = False
    filesystem_scope: str = "none"  # none, session, scoped, full
    subprocess_allowed: bool = False
    max_concurrent_tools: int = 1

    def allows_resource(self, resource_type: ResourceType) -> bool:
        """Check if this constraint set allows the given resource type."""
        if resource_type == ResourceType.NETWORK:
            return self.network_allowed
        elif resource_type == ResourceType.FILESYSTEM:
            return self.filesystem_scope != "none"
        elif resource_type == ResourceType.SUBPROCESS:
            return self.subprocess_allowed
        elif resource_type == ResourceType.TOOL_EXECUTION:
            return True
        return False


# Ring-to-resource constraint mapping
RING_CONSTRAINTS: dict[ExecutionRing, ResourceConstraints] = {
    ExecutionRing.RING_0_ROOT: ResourceConstraints(
        network_allowed=True,
        filesystem_writable=True,
        filesystem_scope="full",
        subprocess_allowed=True,
        max_concurrent_tools=32,
    ),
    ExecutionRing.RING_1_PRIVILEGED: ResourceConstraints(
        network_allowed=True,
        filesystem_writable=True,
        filesystem_scope="full",
        subprocess_allowed=True,
        max_concurrent_tools=16,
    ),
    ExecutionRing.RING_2_STANDARD: ResourceConstraints(
        network_allowed=True,
        network_allowlist=[],  # empty = all allowed at this ring
        filesystem_writable=True,
        filesystem_scope="scoped",
        subprocess_allowed=True,
        max_concurrent_tools=8,
    ),
    ExecutionRing.RING_3_SANDBOX: ResourceConstraints(
        network_allowed=False,
        filesystem_writable=False,
        filesystem_scope="none",
        subprocess_allowed=False,
        max_concurrent_tools=2,
    ),
}

# A redirection operator (with an optional fd number at the start of a word, "&>",
# ">&", ">|" or "<<<") and the shell word that is its target. The target keeps
# quoted parts ("...", '...', $'...', $"...") and backslash escapes together with
# the plain characters around them, so a quoted or escaped space stays inside it.
# An unterminated quote runs to the end of the command.
# Quoted parts and backslash escapes outside a redirection are matched as "quoted"
# so that a "<" or ">" inside them (echo ">", FOO='<' ls, echo \>) is left as it is:
# the shell reads those as part of a word, not as a redirection. Only a closed quote
# counts here, so an unterminated quote is handled as before.
_REDIRECTION = re.compile(
    r"(?P<quoted>"
    r"\$'(?:[^'\\]|\\.)*'"
    r'|\$?"(?:[^"\\]|\\.)*"'
    r"|'[^']*'"
    r"|\\."
    r")"
    r"|(?:(?<![^\s;&|()`])\d+|&)?[<>]+[&|]?\s*"
    r"(?P<target>(?:"
    r"\$'(?:[^'\\]|\\.)*'?"
    r'|\$?"(?:[^"\\]|\\.)*"?'
    r"|'[^']*'?"
    r"|\\.?"
    r"|[^\s;&|<>()`'\"\\]"
    r")*)",
    re.DOTALL,
)


def _remove_quoting(text: str) -> str:
    """Remove the quotes and backslashes the shell drops before running a command.

    e.g., "'curl'" -> "curl", "c\\url" -> "curl", "$'curl'" -> "curl"
    """
    return re.sub(r"[\"'\\]", "", re.sub(r"\$(?=[\"'])", "", text))


def _join_continued_lines(text: str) -> str:
    """Remove the backslash-newline pairs the shell drops before it reads words.

    e.g., "cu\\<newline>rl" -> "curl", while an escaped backslash ("\\\\") stays
    """
    return re.sub(
        r"\\(.)", lambda m: "" if m.group(1) == "\n" else m.group(0), text, flags=re.DOTALL
    )


# A shell word (quoted parts, backslash escapes and plain characters kept together,
# as in a redirection target) or a single operator character between words
_SHELL_TOKEN = re.compile(
    r"(?P<word>(?:"
    r"\$'(?:[^'\\]|\\.)*'?"
    r'|\$?"(?:[^"\\]|\\.)*"?'
    r"|'[^']*'?"
    r"|\\.?"
    r"|[^\s;&|<>()`'\"\\]"
    r")+)"
    r"|(?P<operator>[\n;&|<>()`])",
    re.DOTALL,
)

# A variable assignment the shell makes before running the command, e.g., "FOO=x",
# "FOO+=x" or "a[0]=x". The name must not be quoted or escaped
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")


@dataclass(frozen=True)
class _WrapperSyntax:
    """How a command that runs another command reads its options.

    Options are read like getopt_long in "+" mode: they stop at the first operand
    or after "--", short options can be grouped, an option argument can be attached
    or be the next word, and a long option can be shortened to a unique prefix.

    Attributes:
        flags: Short options without an argument.
        with_argument: Short options that take an argument.
        optional_argument: Short options whose argument, if any, is attached to
            them (``xargs -l1``).
        long_options: Long option names, mapped to 0 (no argument), 1 (required
            argument) or 2 (optional argument, only when attached with "=").
        no_command: Options after which the wrapper runs no command (e.g. "--help").
        unsupported: Options whose effect on the command cannot be checked.
        operands: Operands read before the command (the duration of ``timeout``).
        assignments: Whether ``NAME=VALUE`` words before the command are read
            (``env``, ``sudo``), including a lone "-" right after the options.
        interleaved_assignments: Whether ``NAME=VALUE`` words can also come
            between the options (``sudo``). Such a word does not start with "/"
            or "=".
        numeric_options: Whether "-N", "--N" and "-+N" set a value (``nice``).
    """

    flags: str = ""
    with_argument: str = ""
    optional_argument: str = ""
    long_options: dict[str, int] = field(default_factory=dict)
    no_command: frozenset[str] = frozenset({"--help", "--version"})
    unsupported: frozenset[str] = frozenset()
    operands: int = 0
    assignments: bool = False
    interleaved_assignments: bool = False
    numeric_options: bool = False


_HELP_AND_VERSION = {"help": 0, "version": 0}

# Commands that run the command named by a later word. The option tables follow
# GNU coreutils, GNU time, GNU findutils xargs, sudo and OpenBSD doas, and the
# bash builtins and the "time" keyword.
_WRAPPERS: dict[str, _WrapperSyntax] = {
    "builtin": _WrapperSyntax(long_options={"help": 0}),
    "command": _WrapperSyntax(
        flags="pvV", long_options={"help": 0}, no_command=frozenset({"--help", "-v", "-V"})
    ),
    "env": _WrapperSyntax(
        flags="iv0",
        with_argument="uCS",
        long_options={
            "ignore-environment": 0,
            "null": 0,
            "unset": 1,
            "chdir": 1,
            "split-string": 1,
            "default-signal": 2,
            "ignore-signal": 2,
            "block-signal": 2,
            "list-signal-handling": 0,
            "debug": 0,
            **_HELP_AND_VERSION,
        },
        # -S splits its argument into more words, which may hold the command
        unsupported=frozenset({"-S", "--split-string"}),
        assignments=True,
    ),
    "doas": _WrapperSyntax(
        flags="Lns",
        with_argument="aCu",
        long_options={},
        # -L and -C exit without running the command
        no_command=frozenset({"-L", "-C"}),
        # -s runs a shell instead of a command
        unsupported=frozenset({"-s"}),
    ),
    "exec": _WrapperSyntax(flags="cl", with_argument="a", long_options={"help": 0}),
    "nice": _WrapperSyntax(
        with_argument="n",
        long_options={"adjustment": 1, **_HELP_AND_VERSION},
        numeric_options=True,
    ),
    "nohup": _WrapperSyntax(long_options=_HELP_AND_VERSION),
    "sudo": _WrapperSyntax(
        flags="ABbEeHiKklNnPSsVv",
        with_argument="aCcDgpRrTtUu",
        long_options={
            "askpass": 0,
            "auth-type": 1,
            "background": 0,
            "bell": 0,
            "close-from": 1,
            "login-class": 1,
            "chdir": 1,
            "preserve-env": 2,
            "edit": 0,
            "group": 1,
            "set-home": 0,
            "host": 1,
            "login": 0,
            "remove-timestamp": 0,
            "reset-timestamp": 0,
            "list": 0,
            "no-update": 0,
            "non-interactive": 0,
            "preserve-groups": 0,
            "prompt": 1,
            "chroot": 1,
            "role": 1,
            "stdin": 0,
            "shell": 0,
            "type": 1,
            "command-timeout": 1,
            "other-user": 1,
            "user": 1,
            "validate": 0,
            **_HELP_AND_VERSION,
        },
        # Editing files, listing privileges, validating or removing the cached
        # credentials and printing the version run no command
        no_command=frozenset(
            {
                "--help",
                "--version",
                "-V",
                "-e",
                "--edit",
                "-l",
                "--list",
                "-v",
                "--validate",
                "-K",
                "--remove-timestamp",
            }
        ),
        # -i and -s run a shell, which reads the command words again, and -h is
        # either --help or --host with an attached or a following argument
        unsupported=frozenset({"-i", "--login", "-s", "--shell", "-h"}),
        assignments=True,
        # sudo reads an environment word and then resumes reading options
        interleaved_assignments=True,
    ),
    "stdbuf": _WrapperSyntax(
        with_argument="ioe",
        long_options={"input": 1, "output": 1, "error": 1, **_HELP_AND_VERSION},
    ),
    "time": _WrapperSyntax(
        flags="apqVv",
        with_argument="fo",
        long_options={
            "append": 0,
            "format": 1,
            "output": 1,
            "portability": 0,
            "quiet": 0,
            "verbose": 0,
            **_HELP_AND_VERSION,
        },
        no_command=frozenset({"--help", "--version", "-V"}),
    ),
    "timeout": _WrapperSyntax(
        flags="fpv",
        with_argument="ks",
        long_options={
            "foreground": 0,
            "kill-after": 1,
            "preserve-status": 0,
            "signal": 1,
            "verbose": 0,
            **_HELP_AND_VERSION,
        },
        operands=1,
    ),
    "xargs": _WrapperSyntax(
        flags="0oprtx",
        with_argument="aEILnsPd",
        optional_argument="eil",
        long_options={
            "null": 0,
            "arg-file": 1,
            "delimiter": 1,
            "eof": 2,
            "replace": 2,
            "max-lines": 2,
            "max-args": 1,
            "open-tty": 0,
            "interactive": 0,
            "no-run-if-empty": 0,
            "max-chars": 1,
            "verbose": 0,
            "show-limits": 0,
            "exit": 0,
            "max-procs": 1,
            "process-slot-var": 1,
            **_HELP_AND_VERSION,
        },
    ),
}


def _wrapped_command_index(words: list[str | None], i: int, syntax: _WrapperSyntax) -> int | None:
    """Return the index in ``words`` of the command run by the wrapper at ``i - 1``.

    ``words`` are the unquoted shell words, with None for an operator. An operator
    or the end of ``words`` in place of the command means the wrapper runs no
    command, and None means its options cannot be read, so the command it runs
    is unknown.
    """
    end = len(words)
    while i < end and words[i] is not None:
        arg = words[i]
        if syntax.numeric_options and re.match(r"-[-+]?\d", arg):
            i += 1
            continue
        if arg == "--":
            i += 1
            break
        if arg.startswith("--"):
            name, has_value, _ = arg[2:].partition("=")
            matches = [option for option in syntax.long_options if option == name]
            if not matches:
                matches = [option for option in syntax.long_options if option.startswith(name)]
            if not name or len(matches) != 1:
                return None
            option = matches[0]
            kind = syntax.long_options[option]
            if f"--{option}" in syntax.unsupported or (kind == 0 and has_value):
                return None
            if f"--{option}" in syntax.no_command:
                return end
            if kind == 1 and not has_value:
                i += 1
                if i == end or words[i] is None:
                    return None
            i += 1
            continue
        if arg.startswith("-") and arg != "-":
            for position, letter in enumerate(arg[1:], start=2):
                if f"-{letter}" in syntax.unsupported:
                    return None
                if f"-{letter}" in syntax.no_command:
                    return end
                if letter in syntax.flags:
                    continue
                if letter in syntax.optional_argument:
                    break
                if letter not in syntax.with_argument:
                    return None
                # The rest of the word is the argument, or else the next word is
                if position == len(arg):
                    i += 1
                    if i == end or words[i] is None:
                        return None
                break
            i += 1
            continue
        if syntax.interleaved_assignments and "=" in arg and arg[0] not in "/=":
            i += 1
            continue
        break
    if syntax.assignments:
        if i < end and words[i] == "-":
            i += 1
        while i < end and words[i] is not None and "=" in words[i]:
            i += 1
    for _ in range(syntax.operands):
        if i < end and words[i] is not None:
            i += 1
    return i


def _command_word_start(text: str) -> int | None:
    """Return where the word naming the first command the shell runs starts.

    Variable assignments before the command ("FOO=x curl") are skipped, and so are
    wrappers that run the command named by a later word ("env -i curl",
    "nohup curl"). A wrapper that runs no command is itself the command
    ("env", "command -v curl"). Returns None if a wrapper's options cannot be
    read, and ``len(text)`` if there is no command word.
    """
    tokens = list(_SHELL_TOKEN.finditer(text))
    words = [
        None if token.lastgroup == "operator" else _remove_quoting(token.group())
        for token in tokens
    ]
    assignments_allowed = True
    i = 0
    while i < len(tokens):
        word = words[i]
        if word is None or word in ("{", "!", "$"):
            assignments_allowed = True
            i += 1
            continue
        if assignments_allowed and _ASSIGNMENT.match(tokens[i].group()):
            i += 1
            continue
        name = word.rsplit("/", 1)[-1].lower()
        syntax = _WRAPPERS.get(name)
        if syntax is None:
            return tokens[i].start()
        command_index = _wrapped_command_index(words, i + 1, syntax)
        if command_index is None:
            return None
        if command_index == len(words) or words[command_index] is None:
            return tokens[i].start()
        i = command_index
        # "time" is also a shell keyword that comes before assignments
        assignments_allowed = name == "time"
    return len(text)


@dataclass
class RingCheckResult:
    """Result of a ring enforcement check."""

    allowed: bool
    required_ring: ExecutionRing
    agent_ring: ExecutionRing
    eff_score: float
    reason: str
    requires_consensus: bool = False
    requires_sre_witness: bool = False
    denied_resources: list[ResourceType] = field(default_factory=list)


@dataclass
class CommandCheckResult:
    """Result of a command denylist check.

    Attributes:
        allowed: Whether the command is allowed (not in denylist).
        reason: Human-readable explanation of the decision.
        command: The command that was checked (base command name, without args).
        matched_denylist_entry: The denylist entry that matched, if denied.
    """

    allowed: bool
    reason: str
    command: str
    matched_denylist_entry: str | None = None


class RingEnforcer:
    """Ring enforcer with resource constraint validation.

    Ring 0 (Root): Always denied for agents (system-only).
    Ring 1 (Privileged): Full network, full filesystem, subprocess allowed.
    Ring 2 (Standard): Allowlisted network, scoped filesystem, subprocess allowed.
    Ring 3 (Sandbox): No network, read-only filesystem, no subprocess.
    """

    RING_1_THRESHOLD = RING_1_ENFORCER_THRESHOLD

    def __init__(self) -> None:
        pass

    def check(
        self,
        agent_ring: ExecutionRing,
        action: ActionDescriptor,
        eff_score: float,
        has_consensus: bool = False,
        has_sre_witness: bool = False,
    ) -> RingCheckResult:
        """Check if an agent can perform an action given their ring level.

        Validates both ring-level access and resource constraints.
        """
        required = action.required_ring

        # Ring 0: always denied for agents
        if required == ExecutionRing.RING_0_ROOT:
            return RingCheckResult(
                allowed=False,
                required_ring=required,
                agent_ring=agent_ring,
                eff_score=eff_score,
                reason="Ring 0 actions require SRE Witness attestation",
                requires_sre_witness=True,
            )

        # Agent's ring must be <= required ring (lower number = more privileged)
        if agent_ring.value > required.value:
            return RingCheckResult(
                allowed=False,
                required_ring=required,
                agent_ring=agent_ring,
                eff_score=eff_score,
                reason=(
                    f"Agent ring {agent_ring.value} insufficient for required ring {required.value}"
                ),
            )

        return RingCheckResult(
            allowed=True,
            required_ring=required,
            agent_ring=agent_ring,
            eff_score=eff_score,
            reason="Access granted",
        )

    def check_resource(
        self,
        agent_ring: ExecutionRing,
        resource_type: ResourceType,
    ) -> RingCheckResult:
        """Check if an agent's ring allows access to a specific resource type.

        Args:
            agent_ring: The agent's current execution ring.
            resource_type: The resource type being requested.

        Returns:
            RingCheckResult indicating whether access is allowed.
        """
        constraints = self.get_constraints(agent_ring)

        if constraints.allows_resource(resource_type):
            return RingCheckResult(
                allowed=True,
                required_ring=agent_ring,
                agent_ring=agent_ring,
                eff_score=0.0,
                reason=f"{resource_type.value} access granted for ring {agent_ring.value}",
            )

        return RingCheckResult(
            allowed=False,
            required_ring=agent_ring,
            agent_ring=agent_ring,
            eff_score=0.0,
            reason=f"{resource_type.value} access denied at ring {agent_ring.value}",
            denied_resources=[resource_type],
        )

    def get_constraints(self, ring: ExecutionRing) -> ResourceConstraints:
        """Get the resource constraints for a given ring.

        Args:
            ring: The execution ring.

        Returns:
            ResourceConstraints for the ring.
        """
        return RING_CONSTRAINTS.get(ring, RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX])

    def compute_ring(self, eff_score: float, has_consensus: bool = False) -> ExecutionRing:
        """Compute ring assignment from trust score."""
        return ExecutionRing.from_eff_score(eff_score, has_consensus)

    def should_demote(self, current_ring: ExecutionRing, eff_score: float) -> bool:
        """Check if an agent should be demoted based on trust drop."""
        appropriate = self.compute_ring(eff_score)
        return appropriate.value > current_ring.value

    def check_command(self, command: str | None) -> CommandCheckResult:
        """Check if a command is allowed by the denylist.

        This method validates whether a command (or command string with arguments)
        is present in the global DENIED_COMMANDS list. The check is performed
        against the base command name (the first command the shell would run).
        Variable assignments before it and wrappers that run it (``env``, ``exec``,
        ``nohup``, ``nice``, ``timeout``, ``stdbuf``, ``time``, ``command``,
        ``builtin``, ``sudo``, ``doas``, ``xargs``) are skipped, and a wrapper whose
        options cannot be read is denied. Matching is case-insensitive to prevent
        bypasses via case variation.

        Args:
            command: The command to check (e.g., "curl", "curl -X POST", "python3").
                     Can be None or empty string.

        Returns:
            CommandCheckResult with allowed status, reason, and the base command name.
        """
        if not command:
            return CommandCheckResult(
                allowed=False,
                reason="Empty or None command is not allowed",
                command="",
                matched_denylist_entry=None,
            )

        # The shell removes a backslash-newline before it reads words, e.g., "cu\<newline>rl"
        stripped = _join_continued_lines(command).strip()
        if not stripped:
            return CommandCheckResult(
                allowed=False,
                reason="Command contains no executable name",
                command="",
                matched_denylist_entry=None,
            )

        # Drop redirections with their targets, which the shell applies before running
        # the command, so a target is never taken for the executable. This runs before
        # the quotes are removed, so a quoted or escaped space stays in the target
        # e.g., ">out curl" -> "curl", "2>&1 curl" -> "curl", '>"my file" curl' -> "curl"
        # A quoted or escaped "<" or ">" is not a redirection, e.g., 'FOO=">" ls' -> "ls"
        targets: list[str] = []

        def drop_redirection(match: re.Match[str]) -> str:
            if match.group("quoted") is not None:
                return match.group()
            targets.append(match.group("target"))
            return " "

        normalized = _REDIRECTION.sub(drop_redirection, stripped)

        # Skip variable assignments and wrappers that run a later word as the command,
        # e.g., "FOO=x curl" -> "curl", "env -i curl" -> "curl", "nohup curl" -> "curl"
        start = _command_word_start(normalized)
        if start is None:
            return CommandCheckResult(
                allowed=False,
                reason="Command runs another command that cannot be determined",
                command="",
                matched_denylist_entry=None,
            )
        normalized = normalized[start:]

        # Remove shell quoting and escapes, which the shell drops before running
        # the command, e.g., "'curl'" -> "curl", "c\url" -> "curl", "$'curl'" -> "curl"
        normalized = _remove_quoting(normalized)

        # Split at whitespace, control operators, redirections, subshells and command
        # substitution so the first command the shell runs is checked
        # e.g., "curl;" -> "curl", "|curl" -> "curl", "curl>out" -> "curl", "$(curl x)" -> "curl"
        tokens = [token for token in re.split(r"[\s;&|<>()`]+", normalized) if token]

        # A redirection to an empty file name ('>"" curl') fails in the shell and
        # the command never runs, so treat it as having no executable name
        if any(target and not _remove_quoting(target) for target in targets):
            tokens = []

        # Skip words that open a group or negate the command that follows them,
        # and the "$" left over from "$(", e.g., "{ curl; }" -> "curl", "! curl" -> "curl"
        while tokens and tokens[0] in ("{", "!", "$"):
            tokens.pop(0)
        base_command = tokens[0] if tokens else ""

        # Match the executable name rather than the path used to invoke it
        # e.g., "/usr/bin/curl" -> "curl", "./bash" -> "bash"
        base_command = base_command.rsplit("/", 1)[-1]

        if not base_command:
            return CommandCheckResult(
                allowed=False,
                reason="Command contains no executable name",
                command="",
                matched_denylist_entry=None,
            )

        base_command_lower = base_command.lower()

        # Check against denylist (case-insensitive match)
        for denied_cmd in DENIED_COMMANDS:
            if base_command_lower == denied_cmd.lower():
                return CommandCheckResult(
                    allowed=False,
                    reason=f"Command '{base_command}' is denied by sandbox policy",
                    command=base_command,
                    matched_denylist_entry=denied_cmd,
                )

        return CommandCheckResult(
            allowed=True,
            reason=f"Command '{base_command}' is allowed",
            command=base_command,
            matched_denylist_entry=None,
        )
