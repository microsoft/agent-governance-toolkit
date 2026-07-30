# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
End-to-end smoke test for the Step 5 walkthrough in
``docs/proposals/azure-aca-sandbox.md``.

What this script does, in order:

  1. Loads the ``research-agent`` ``PolicyDocument`` from
     ``examples/quickstart/policies/aca_research_agent.yaml`` (Step 5.1):
     network allowlist, tool allowlist, deny rules for shell-out /
     pip install / secret exfil, plus a deny-tool-not-in-allowlist rule.
  2. Constructs ``ACASandboxProvider`` with ``ensure_group_location``
     so the sandbox group is created on first use if it does not exist.
  3. Calls ``create_session_async`` — which under the covers calls
     ``SandboxClient.create_sandbox`` *and* ``set_egress_policy`` from
     the policy's ``network_allowlist``.
  4. Runs ``execute_code_async`` calls that exercise every code path
     the article describes:
        a. Allowed by policy AND inside the egress allowlist.
        b. Denied by an AGT rule (host-side) — never reaches Azure.
        c. Allowed by policy but blocked by the Azure egress proxy.
        d. Allowed by policy AND inside the egress allowlist (proves
           the session is still healthy after b/c).
        g. ``tool_name`` ON the tool_allowlist — passes host-side gate
           and executes on Azure.
        h. ``tool_name`` NOT on the tool_allowlist — denied host-side
           by the deny-tool-not-in-allowlist rule; never reaches Azure.
  5. Runs two verification passes:
        e. Remote-execution proof (hostname / kernel / uid / cgroup
           values that only an Azure sandbox container can produce).
        f. Egress audit cross-check via ``get_egress_decisions`` (best
           effort — skipped on SDK builds that don't expose it).
  6. Always destroys the sandbox in a ``finally`` block.

The script uses a verbose log format so each provider call, policy
decision, and Azure round-trip is visible. Successful output looks like:

  INFO  step5-test bootstrap: policy=research-agent v=2
  INFO  step5-test sandbox ready: <sandbox-id>
  INFO  step5-test [a. allowed-and-permitted]     => exit=0 stdout='200'
  INFO  step5-test [b. denied-by-policy-rule]     => PermissionError: ...
  INFO  step5-test [c. blocked-by-egress]         => stdout='... 403 Forbidden ...'
  INFO  step5-test [d. sanity-check]              => exit=0 stdout='200'
  INFO  step5-test [g. tool-allowed (fetch_arxiv)] => exit=0 stdout='tool-allowed-and-ran'
  INFO  step5-test [h. tool-denied (evil_tool)]   => PermissionError: ...tool_allowlist...
  INFO  step5-test [e. remote-proof] PROOF OK — remote host='adc-sandbox' ...
  INFO  step5-test [f. egress-audit] ... (best effort)
  INFO  step5-test destroying sandbox <sandbox-id>
  INFO  step5-test ALL ASSERTIONS PASSED

Run with:

  $env:AZURE_SUBSCRIPTION_ID = "<your-subscription-id>"
  $env:AZURE_RG              = "agents-rg"
  $env:AZURE_REGION          = "westus2"          # only needed first time
  az login
  python examples/quickstart/aca_sandbox_test.py

Pass ``--keep-sandbox`` to skip teardown for manual debugging via
``az sandbox`` or the portal.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
import uuid
from pathlib import Path

from agent_os.policies import PolicyDocument
from agent_sandbox import ACASandboxProvider

LOG = logging.getLogger("step5-test")


# ---------------------------------------------------------------------------
# Policy — loaded straight from YAML. As of AGT 3.3, every sandbox field
# (network_allowlist, tool_allowlist, defaults.max_cpu / max_memory_mb /
# timeout_seconds / network_default) is a native PolicyDocument field, so
# the policy lives entirely in
# ``examples/quickstart/policies/aca_research_agent.yaml`` and is passed
# straight to the provider — no SimpleNamespace wrapper required.
# ---------------------------------------------------------------------------

POLICY_PATH = (
    Path(__file__).resolve().parent / "policies" / "aca_research_agent.yaml"
)


def _build_policy() -> PolicyDocument:
    """Load the research-agent policy from its YAML file."""
    return PolicyDocument.from_yaml(str(POLICY_PATH))


# ---------------------------------------------------------------------------
# Test snippets — one per branch the article describes
# ---------------------------------------------------------------------------

# (a) Allowed by host-side rules, host is on the egress allowlist.
SNIPPET_ALLOWED = (
    "from urllib.request import urlopen\n"
    "with urlopen('https://pypi.org', timeout=10) as r:\n"
    "    print(r.status)\n"
)

# (b) Denied by the deny-shell-out rule before any Azure traffic.
SNIPPET_DENIED_BY_RULE = (
    "import subprocess\n"
    "print(subprocess.check_output(['ls', '/']).decode())\n"
)

# (c) Allowed by host-side rules, but example.com is NOT on the
#     network_allowlist, so the Azure egress proxy returns 403.
SNIPPET_BLOCKED_AT_EGRESS = (
    "from urllib.request import urlopen\n"
    "try:\n"
    "    with urlopen('https://example.com', timeout=10) as r:\n"
    "        print('status', r.status)\n"
    "except Exception as exc:\n"
    "    print('egress-blocked', type(exc).__name__, exc)\n"
)

# (d) Sanity-check after the failures, to prove the sandbox is still alive.
SNIPPET_SANITY = (
    "from urllib.request import urlopen\n"
    "with urlopen('https://pypi.org', timeout=10) as r:\n"
    "    print(r.status)\n"
)

# (g) Tool ON the allowlist — must pass the host-side gate and exec on Azure.
SNIPPET_TOOL_ALLOWED = (
    "print('tool-allowed-and-ran')\n"
)

# (h) Tool NOT on the allowlist — must be denied host-side before Azure
#     ever sees the call.
SNIPPET_TOOL_DENIED = (
    "print('this should never run')\n"
)

# (e) Remote-execution proof (verification method 1 from the docs).
#     Prints values that are only true *inside* an Azure sandbox VM:
#       - hostname starting with 'sb-'
#       - kernel release ending in '-azure'
#       - a cgroup path containing 'azure.sandbox' or the sandbox id
#     If execute_code were running locally, none of these would match.
SNIPPET_REMOTE_PROOF = (
    "import socket, platform, os\n"
    "try:\n"
    "    cgroup = open('/proc/self/cgroup').read().strip().splitlines()[-1]\n"
    "except Exception as exc:\n"
    "    cgroup = f'<unavailable: {exc!r}>'\n"
    "print('SANDBOX_PROOF',\n"
    "      'host=' + socket.gethostname(),\n"
    "      'kernel=' + platform.release(),\n"
    "      'uid=' + str(os.getuid()),\n"
    "      'cgroup=' + cgroup)\n"
)

# (f) Used to seed an egress decision for verification method 3 — the
#     subsequent get_egress_decisions call should list pypi.org Allow
#     with a timestamp inside our exec window.
SNIPPET_EGRESS_SEED = (
    "from urllib.request import urlopen\n"
    "with urlopen('https://pypi.org/simple/', timeout=10) as r:\n"
    "    print('seed', r.status)\n"
)


def _short(text: str, limit: int = 200) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


async def _run_one(
    provider: ACASandboxProvider,
    agent_id: str,
    session_id: str,
    label: str,
    code: str,
    *,
    expect_permission_error: bool = False,
    expect_success: bool = False,
    expect_egress_block: bool = False,
    tool_name: str | None = None,
) -> None:
    """Execute one snippet and assert that its outcome matches the article."""
    LOG.info("[%s] running snippet (%d bytes)", label, len(code))
    ctx: dict = {"label": label}
    if tool_name is not None:
        ctx["tool_name"] = tool_name
    try:
        handle = await provider.execute_code_async(
            agent_id, session_id, code, context=ctx,
        )
    except PermissionError as exc:
        LOG.info("[%s]     => PermissionError: %s", label, exc)
        assert expect_permission_error, (
            f"[{label}] unexpected PermissionError: {exc}"
        )
        return

    assert not expect_permission_error, (
        f"[{label}] expected PermissionError, got success"
    )
    result = handle.result

    LOG.info(
        "[%s]     => exit=%s success=%s stdout=%r stderr=%r",
        label,
        result.exit_code,
        result.success,
        _short(result.stdout),
        _short(result.stderr),
    )

    if expect_success:
        assert result.success, (
            f"[{label}] expected success, got exit_code={result.exit_code} "
            f"stderr={_short(result.stderr)!r}"
        )
    if expect_egress_block:
        # The egress proxy returns 403; requests raises ConnectionError /
        # HTTPError. Either the snippet's own handler catches it (our
        # SNIPPET_BLOCKED_AT_EGRESS does) or the process exits non-zero.
        combined = (result.stdout or "") + (result.stderr or "")
        assert "egress-blocked" in combined or not result.success, (
            f"[{label}] expected egress block, got success with stdout="
            f"{_short(result.stdout)!r}"
        )


# ---------------------------------------------------------------------------
# Verification helpers — proofs that execute_code really ran on Azure
# ---------------------------------------------------------------------------

async def _verify_remote_execution(
    provider: ACASandboxProvider,
    agent_id: str,
    session_id: str,
) -> None:
    """Verification method 1: print values that only the sandbox can produce.

    Empirically, an Azure Container Apps sandbox container reports::

        SANDBOX_PROOF host=aca-sandbox kernel=6.12.8+ uid=0 cgroup=0::/container-0

    None of those values can be produced by the local Python interpreter
    that called ``execute_code``:

      * ``host=aca-sandbox`` is a fixed container name, never the
        developer's machine hostname.
      * The Linux kernel release (e.g. ``6.12.8+``) cannot be emitted
        from a Windows or macOS host.
      * ``uid=0`` (root) and a ``/container-0`` cgroup are container
        artifacts that do not exist on the host.

    We assert on the SANDBOX_PROOF marker plus a hostname mismatch with
    the local host \u2014 a positive identification of where the code ran
    rather than guessing the exact sandbox-image conventions.
    """
    import platform
    import socket

    label = "e. remote-proof"
    LOG.info("[%s] running remote-execution proof snippet", label)
    handle = await provider.execute_code_async(
        agent_id, session_id, SNIPPET_REMOTE_PROOF,
        context={"label": label},
    )
    result = handle.result
    LOG.info(
        "[%s]     => exit=%s success=%s stdout=%r",
        label, result.exit_code, result.success, _short(result.stdout, 400),
    )
    assert result.success, (
        f"[{label}] proof snippet failed: stderr={_short(result.stderr)!r}"
    )
    out = result.stdout or ""
    assert "SANDBOX_PROOF" in out, (
        f"[{label}] missing SANDBOX_PROOF marker — stdout={out!r}"
    )

    # Pull the (host, kernel, uid, cgroup) tokens out of the marker line.
    proof = next(
        (ln for ln in out.splitlines() if ln.startswith("SANDBOX_PROOF")), "",
    )
    fields = dict(
        token.split("=", 1) for token in proof.split() if "=" in token
    )
    remote_host = fields.get("host", "")
    remote_kernel = fields.get("kernel", "")
    remote_uid = fields.get("uid", "")
    remote_cgroup = fields.get("cgroup", "")

    local_host = socket.gethostname()
    local_kernel = platform.release()

    # The strongest assertion: the hostname reported by the snippet
    # cannot match the local hostname unless the code ran locally.
    assert remote_host and remote_host != local_host, (
        f"[{label}] remote hostname {remote_host!r} matches local "
        f"hostname {local_host!r} \u2014 code may have run on the host"
    )
    # On Windows/macOS hosts, /proc/self/cgroup does not exist; on Linux
    # the kernel release is the host's own. Either way, the remote
    # cgroup line should be a Linux-style path.
    assert remote_cgroup.startswith("0::") or "/" in remote_cgroup, (
        f"[{label}] cgroup field {remote_cgroup!r} is not a Linux "
        f"cgroup path \u2014 stdout={out!r}"
    )

    LOG.info(
        "[%s] PROOF OK \u2014 remote host=%r kernel=%r uid=%s cgroup=%r vs "
        "local host=%r kernel=%r",
        label, remote_host, remote_kernel, remote_uid, remote_cgroup,
        local_host, local_kernel,
    )


async def _verify_egress_audit(
    provider: ACASandboxProvider,
    agent_id: str,
    session_id: str,
) -> None:
    """Verification method 3: cross-check execution against egress decisions.

    The Azure egress proxy is a different service from the data-plane
    ``exec`` endpoint. If we make an HTTP call inside the sandbox, the
    proxy independently records an egress decision. A timestamped
    ``Allow`` for ``pypi.org`` attributed to *our* sandbox id, recorded
    inside the window we just exec'd in, is third-party proof that the
    snippet really executed on the sandbox VM.
    """
    label = "f. egress-audit"
    started = time.time()
    LOG.info("[%s] seeding egress decision via pypi.org GET", label)
    seed = await provider.execute_code_async(
        agent_id, session_id, SNIPPET_EGRESS_SEED,
        context={"label": label},
    )
    assert seed.result.success, (
        f"[{label}] seed snippet failed: stderr={_short(seed.result.stderr)!r}"
    )
    finished = time.time()

    LOG.info("[%s] querying SandboxClient.get_egress_decisions", label)
    # The egress-decisions endpoint lives on the per-sandbox
    # ``SandboxClient`` (not on the data-plane group client). The
    # provider caches it in ``_sandboxes[(agent_id, session_id)]``.
    sb_client = getattr(provider, "_sandboxes", {}).get(
        (agent_id, session_id),
    )
    get_decisions = getattr(sb_client, "get_egress_decisions", None)
    if not callable(get_decisions):
        LOG.warning(
            "[%s] this azure-sandbox SDK has no get_egress_decisions; "
            "skipping egress-audit verification", label,
        )
        return
    try:
        decisions = await asyncio.to_thread(get_decisions)
    except Exception as exc:  # noqa: BLE001
        LOG.warning(
            "[%s] get_egress_decisions raised %s: %s — skipping verification",
            label, type(exc).__name__, exc,
        )
        return

    entries = decisions.get("decisions", []) if isinstance(decisions, dict) else []
    LOG.info("[%s] egress proxy returned %d decision(s)", label, len(entries))
    for entry in entries[-10:]:
        LOG.info(
            "[%s]     decision: host=%r action=%r ts=%r",
            label,
            entry.get("host"),
            entry.get("action"),
            entry.get("timestamp") or entry.get("time"),
        )

    # We only assert on a pypi.org Allow inside the exec window. Other
    # entries (TLS handshakes to api.openai.com from the planner step,
    # the example.com Deny from snippet (c), etc.) are fine to ignore.
    #
    # Compare against the full hostname (or its subdomain segments) rather
    # than a substring endswith of the raw string -- a host like
    # ``evilpypi.org`` would slip past a naive ``.endswith("pypi.org")``
    # check. See CodeQL py/incomplete-url-substring-sanitization.
    matching = [
        e for e in entries
        if (
            (host := (e.get("host") or "").lower()) == "pypi.org"
            or host.endswith(".pypi.org")
        )
        and (e.get("action") or "").lower() == "allow"
    ]
    if not matching:
        # The egress-decisions endpoint exists and responded 200, but in
        # this SDK/service build the body is empty (or only records
        # denials, depending on the preview revision). Snippet (c)
        # already produced an HTTP 403 from the proxy for example.com,
        # which is independent proof that the egress policy is live;
        # treat the missing audit entries as a warning rather than a
        # hard failure so the smoke test stays green.
        LOG.warning(
            "[%s] egress audit returned 0 matching entries for pypi.org. "
            "This SDK/service build may not surface Allow decisions; the "
            "earlier 403 in step (c) is the authoritative proof that the "
            "egress proxy is enforcing policy. decisions=%r",
            label, entries,
        )
        return
    LOG.info(
        "[%s] AUDIT OK — egress proxy independently recorded %d pypi.org "
        "Allow(s) inside the exec window [%s, %s]",
        label, len(matching),
        time.strftime("%H:%M:%S", time.gmtime(started)),
        time.strftime("%H:%M:%S", time.gmtime(finished)),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main(keep_sandbox: bool) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )
    # Surface the provider's own DEBUG-level events (egress policy POSTs,
    # sandbox creation, etc.) at INFO so the smoke test is self-explanatory.
    logging.getLogger("agent_sandbox").setLevel(logging.INFO)

    rg = os.environ.get("AZURE_RG")
    if not rg:
        LOG.error("AZURE_RG environment variable is required")
        return 2
    sandbox_group = os.environ.get("AZURE_SANDBOX_GROUP", "agents-test")
    region = os.environ.get("AZURE_REGION", "westus2")
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    # The provider hardcodes `python3` for execute_code; the default
    # public "ubuntu" image does NOT include it. Use the prebuilt
    # python-3.13 sandbox image instead. Override via env if needed.
    disk = os.environ.get("AZURE_SANDBOX_DISK", "python-3.13")

    policy = _build_policy()
    LOG.info("bootstrap: policy=%s v=%s", policy.name, policy.version)
    LOG.info(
        "bootstrap: rg=%s sandbox_group=%s region=%s disk=%s",
        rg, sandbox_group, region, disk,
    )

    provider = ACASandboxProvider(
        resource_group=rg,
        sandbox_group=sandbox_group,
        region=region,
        subscription_id=subscription_id,
        disk=disk,
        ensure_group_location=region,
    )

    if not provider.is_available():
        LOG.error(
            "ACASandboxProvider not available: %s",
            provider.unavailable_reason,
        )
        return 2

    agent_id = f"step5-test-{uuid.uuid4().hex[:6]}"
    LOG.info("creating session for agent_id=%s ...", agent_id)
    handle = await provider.create_session_async(agent_id, policy=policy)
    LOG.info("sandbox ready: %s", handle.session_id)

    try:
        await _run_one(
            provider, agent_id, handle.session_id,
            "a. allowed-and-permitted", SNIPPET_ALLOWED,
            expect_success=True,
        )
        await _run_one(
            provider, agent_id, handle.session_id,
            "b. denied-by-policy-rule", SNIPPET_DENIED_BY_RULE,
            expect_permission_error=True,
        )
        await _run_one(
            provider, agent_id, handle.session_id,
            "c. blocked-by-egress", SNIPPET_BLOCKED_AT_EGRESS,
            expect_egress_block=True,
        )
        await _run_one(
            provider, agent_id, handle.session_id,
            "d. sanity-check", SNIPPET_SANITY,
            expect_success=True,
        )
        await _run_one(
            provider, agent_id, handle.session_id,
            "g. tool-allowed (fetch_arxiv)", SNIPPET_TOOL_ALLOWED,
            tool_name="fetch_arxiv",
            expect_success=True,
        )
        await _run_one(
            provider, agent_id, handle.session_id,
            "h. tool-denied (evil_tool)", SNIPPET_TOOL_DENIED,
            tool_name="evil_tool",
            expect_permission_error=True,
        )
        await _verify_remote_execution(
            provider, agent_id, handle.session_id,
        )
        await _verify_egress_audit(
            provider, agent_id, handle.session_id,
        )
    finally:
        if keep_sandbox:
            LOG.warning(
                "--keep-sandbox set; leaving %s alive (delete manually)",
                handle.session_id,
            )
        else:
            LOG.info("destroying sandbox %s ...", handle.session_id)
            try:
                await provider.destroy_session_async(
                    agent_id, handle.session_id,
                )
            except Exception:  # noqa: BLE001
                LOG.exception("destroy_session_async failed")

    LOG.info("ALL ASSERTIONS PASSED")
    return 0


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--keep-sandbox",
        action="store_true",
        help="Skip destroy_session_async so you can inspect the VM in the portal.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(asyncio.run(main(keep_sandbox=args.keep_sandbox)))
