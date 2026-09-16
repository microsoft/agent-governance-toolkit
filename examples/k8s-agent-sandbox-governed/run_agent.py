#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Upload and run a local script inside a kubernetes-sigs/agent-sandbox pod,
with every command policy-checked by AGT before it is dispatched.

kubernetes-sigs/agent-sandbox provides Kubernetes-native execution isolation
(pod-level, NetworkPolicy-scoped) but no semantic policy over *what* an
agent asks a sandbox to run — its own docs note network policy only covers
L3/L4, not command content. AGT's govern() fills that gap: it is evaluated
in this driving script's own process, before the command is sent to the
sandbox pod's execution API, so a denied command never reaches the pod at
all (rather than reaching it and being caught/mitigated by isolation).

Usage:
  pip install -r requirements.txt
  python run_agent.py my_tool.sh --interpreter bash -- --flag value
  python run_agent.py agent.py --warmpool python-warmpool --namespace agent-sandbox-demo
"""
import argparse
import os
import re
import shlex
import sys
from pathlib import Path

from agentmesh.governance import GovernanceDenied, govern
from k8s_agent_sandbox import SandboxClient
from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig

POLICY_PATH = Path(__file__).resolve().parent / "policy.yaml"

# Fork bombs and pipe-to-shell installers are inherently about shell syntax
# (subshell/pipe metacharacters) rather than a single command's argv, so
# they stay regex-based.
#
# rm/mkfs/dd are ALSO matched here on raw text, as a second layer alongside
# the parsed-argv check in _is_destructive_segment. The argv check resolves
# quoting/flag-reordering bypasses (`r\m -rf /`, `rm '-rf' /`, `rm -r -f /`)
# that a raw regex would miss, but it only ever sees a single already-split
# command segment - it can't see through every shape a shell can wrap that
# segment in (env-var prefixes, `nohup`/`timeout`/`exec`/`eval`/`busybox`/
# `doas`, `su -c '...'`, `bash -c '...'`, subshells `(...)`, brace groups
# `{ ...; }`, `if`/`for`/function bodies, `find -exec ... +`, redirections
# before the command, a leading `!`, or the command showing up inside a
# script body's `os.system(...)`/`subprocess.run(..., shell=True)` string
# rather than as shell syntax at all). A raw substring match on the command
# name and its flags catches all of those without needing to parse each
# wrapper's own grammar - `\b` boundaries keep `transform -rf foo` benign.
_DESTRUCTIVE_SYNTAX_PATTERNS = [
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",  # fork bomb
    r"curl[^|]*\|\s*(sh|bash)\b",
    r"wget[^|]*\|\s*(sh|bash)\b",
    r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r",
    r"\bmkfs\b",
    r"\bdd\s+if=",
]
_CREDENTIAL_EXFIL_PATTERNS = [
    r"(curl|wget|nc)\b.*\$(AWS_[A-Z_]+|KUBECONFIG)",
    r"cat\s+.*kube/config.*(curl|nc)",
]
# sudo flags that consume the following token as their own argument (not the
# start of the wrapped command), e.g. `sudo -u root rm -rf /` must still
# resolve to `rm -rf /` rather than stopping at the "root" token.
_SUDO_FLAGS_WITH_ARG = {"-u", "-g", "-h", "-p", "-U", "-r", "-t", "-C", "-a", "-T"}
# $(...) / `...` command substitution, one level of nesting - good enough to
# pull `rm -rf /` out of `$(rm -rf /)` without a full shell parser.
_SUBSHELL_PATTERN = re.compile(r"\$\(([^$()]*)\)|`([^`]*)`")


def _flags(tokens: list[str]) -> list[str]:
    # Tokens up to (not including) a bare "--" end-of-options marker, so
    # `rm -- --recursive --force` (real filenames, not flags) isn't flagged.
    if "--" in tokens:
        return tokens[: tokens.index("--")]
    return tokens


def _has_flag(tokens: list[str], short: str, long_name: str) -> bool:
    # Checks parsed argv tokens, not the raw string, so quoting/escaping
    # ("-r -f", "'-rf'") can't hide a flag the shell would still honor.
    for t in tokens:
        if t == long_name:
            return True
        if t.startswith("-") and not t.startswith("--") and short.lower() in t.lower():
            return True
    return False


def _extract_subshells(text: str) -> list[str]:
    found = []
    for m in _SUBSHELL_PATTERN.finditer(text):
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        found.append(inner)
        found.extend(_extract_subshells(inner))  # nested $(...) inside a substitution
    return found


def _line_segments(line: str) -> list[list[str]] | None:
    """Tokenizes a shell line and splits it into command segments on `;`,
    `&&`, `||`, `&` and `|`, so each chained/piped command is checked on its
    own instead of only the first one on the line. Returns None if the line
    can't be tokenized (fail-safe: caller treats it as destructive).
    """
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok and set(tok) <= set("|&;"):
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _strip_wrapper(tokens: list[str]) -> list[str]:
    """Strips `sudo`/`env`/`xargs` wrapper prefixes (and their own flags or
    env-var assignments) so e.g. `sudo rm -rf /` and `env rm -rf /` resolve
    to the same argv as `rm -rf /` for the checks below.
    """
    while tokens:
        exe = os.path.basename(tokens[0])
        if exe in ("sudo", "xargs"):
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                flag = tokens[0]
                tokens = tokens[1:]
                if flag in _SUDO_FLAGS_WITH_ARG and tokens:
                    tokens = tokens[1:]
            continue
        if exe == "env":
            tokens = tokens[1:]
            while tokens and (tokens[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0])):
                tokens = tokens[1:]
            continue
        break
    return tokens


def _is_destructive_segment(tokens: list[str]) -> bool:
    """Token-aware rm/mkfs/dd check for a single (already-split) command segment.

    Uses shlex so quoting/escaping that a POSIX shell would resolve to a
    plain `rm -rf` (or `mkfs`, `dd`) can't hide the command from a
    raw-string regex.
    """
    tokens = _strip_wrapper(tokens)
    if not tokens:
        return False
    exe = os.path.basename(tokens[0])  # strips a path prefix like /bin/rm
    args = _flags(tokens[1:])
    if exe == "rm":
        return _has_flag(args, "r", "--recursive") and _has_flag(args, "f", "--force")
    if exe == "mkfs" or exe.startswith("mkfs."):
        return True
    if exe == "dd":
        return any(t.startswith("if=") for t in tokens[1:])  # order-independent
    return False


def _is_destructive_text(text: str) -> bool:
    # Raw-text layer first (see _DESTRUCTIVE_SYNTAX_PATTERNS) - catches
    # wrapper/eval/subshell/redirection shapes the segment/argv layer below
    # can't see through, and also fires on script bodies where the command
    # is embedded in another language's string literal (e.g. os.system(...)).
    if any(re.search(p, text, re.IGNORECASE) for p in _DESTRUCTIVE_SYNTAX_PATTERNS):
        return True
    lines = list(text.splitlines())
    for line in list(lines):
        lines.extend(_extract_subshells(line))  # also check inside $(...) / `...`
    for line in lines:
        segments = _line_segments(line)
        if segments is None:
            return True  # unparseable quoting - fail safe, treat as destructive
        if any(_is_destructive_segment(segment) for segment in segments):
            return True
    return False


def _classify_command(command: str, script_content: str = "") -> str:
    """Pre-classify a command into a discrete action type for policy evaluation.

    AGT's policy condition DSL only supports equality/membership checks on
    context fields, not substring matching — so free-text pattern matching
    happens here, before the governed call. ``command`` is just the
    interpreter invocation (e.g. "bash foo.sh"); the actual risk usually
    lives in the uploaded script body, so ``script_content`` is scanned too.

    ``command`` and ``script_content`` are matched independently (rather than
    concatenated into one string) so a pattern can't span the boundary
    between them, e.g. "curl" appearing at the end of ``command`` and
    "| sh" appearing at the start of ``script_content`` should not combine
    into a spurious cross-boundary match.
    """
    texts = (command, script_content)
    if any(_is_destructive_text(t) for t in texts):
        return "destructive"
    if any(re.search(p, t, re.IGNORECASE) for p in _CREDENTIAL_EXFIL_PATTERNS for t in texts):
        return "credential_exfil"
    return "shell_exec"


def main() -> int:
    # argparse.REMAINDER greedily swallows everything after the script
    # positional, including our own flags (e.g. --warmpool foo) if they're
    # placed after it. Split on a literal "--" ourselves so our options can
    # appear anywhere before it, and only the script's own args follow it.
    argv = sys.argv[1:]
    if "--" in argv:
        sep = argv.index("--")
        own_argv, script_args = argv[:sep], argv[sep + 1:]
    else:
        own_argv, script_args = argv, []

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("script", type=Path, help="Local path to the script to run in the sandbox")
    parser.add_argument("--interpreter", default="python3", help="Interpreter used to invoke the script (python3, bash, node, ...)")
    parser.add_argument("--warmpool", default="python-warmpool", help="SandboxWarmPool to draw the sandbox from")
    parser.add_argument("--namespace", default="agent-sandbox-demo", help="Namespace containing the warm pool")
    parser.add_argument("--timeout", type=int, default=60, help="Command execution timeout in seconds")
    args = parser.parse_args(own_argv)

    if not args.script.is_file():
        parser.error(f"script not found: {args.script}")

    remote_name = args.script.name
    # k8s-agent-sandbox's commands.run() only accepts a single shell command
    # string (no argv-list/non-shell invocation), so script_args are
    # shell-quoted with shlex.join rather than naively space-joined. This
    # keeps each arg a single token for whatever shell the sandbox pod uses
    # to execute it, closing off metacharacters (;, |, $(), backticks, etc.)
    # in script_args from being interpreted as additional shell syntax.
    command = shlex.join([args.interpreter, remote_name, *script_args])

    # Read the script exactly once. Classifying and uploading from independently
    # taken reads would let a file swapped between the two reads be approved as
    # the safe version but executed as whatever the second read picked up.
    script_bytes = args.script.read_bytes()
    script_text = script_bytes.decode(errors="ignore")
    action_type = _classify_command(command, script_text)

    # Claim a sandbox pod only once the action is dispatched, so a denied
    # command never costs a warm-pool claim.
    sandbox = None

    def _dispatch(action: dict):
        nonlocal sandbox
        client = SandboxClient(connection_config=SandboxLocalTunnelConnectionConfig())
        sandbox = client.create_sandbox(warmpool=args.warmpool, namespace=args.namespace)
        sandbox.files.write(remote_name, script_bytes)
        return sandbox.commands.run(action["command"], timeout=args.timeout)

    governed_run = govern(
        _dispatch,
        policy=str(POLICY_PATH),
        agent_id=f"run_agent:{args.namespace}",
    )
    try:
        try:
            result = governed_run(action={"type": action_type, "command": command})
        except GovernanceDenied as e:
            print(f"Command blocked by governance policy: {e}", file=sys.stderr)
            return 1

        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.exit_code
    finally:
        if sandbox is not None:
            sandbox.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
