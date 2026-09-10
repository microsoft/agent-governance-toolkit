#!/usr/bin/env python3
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
# they stay regex-based. rm/mkfs/dd are matched on parsed argv instead (see
# _is_destructive_line) because a raw-string regex here is trivially bypassed
# by shell quoting (`r\m -rf /`, `rm '-rf' /`) or flag reordering
# (`rm -r -f /`, `rm --recursive --force /`).
_DESTRUCTIVE_SYNTAX_PATTERNS = [
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",  # fork bomb
    r"curl[^|]*\|\s*(sh|bash)\b",
    r"wget[^|]*\|\s*(sh|bash)\b",
]
_CREDENTIAL_EXFIL_PATTERNS = [
    r"(curl|wget|nc)\b.*\$(AWS_[A-Z_]+|KUBECONFIG)",
    r"cat\s+.*kube/config.*(curl|nc)",
]


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


def _is_destructive_line(line: str) -> bool:
    """Token-aware rm/mkfs/dd check for a single shell line.

    Uses shlex so quoting/escaping that a POSIX shell would resolve to a
    plain `rm -rf` (or `mkfs`, `dd`) can't hide the command from a
    raw-string regex. Doesn't see chaining/substitution within the line
    (`;`, `&&`, `$()`, pipes) — that's covered by _DESTRUCTIVE_SYNTAX_PATTERNS
    for the specific patterns above, not a general shell parse.
    """
    try:
        tokens = shlex.split(line)
    except ValueError:
        return True  # unparseable quoting - fail safe, treat as destructive
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
    if any(re.search(p, text, re.IGNORECASE) for p in _DESTRUCTIVE_SYNTAX_PATTERNS):
        return True
    return any(_is_destructive_line(line) for line in text.splitlines())


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
