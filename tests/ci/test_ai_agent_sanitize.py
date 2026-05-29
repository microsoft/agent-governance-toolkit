# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Behavioral tests for the AI agent runner sanitization helpers.

The helpers live in ``.github/actions/ai-agent-runner/lib/sanitize.mjs`` and
are concatenated into the runtime ``ai-agent-runner.mjs`` by ``action.yml``.
We spawn a Node subprocess and drive the exported functions directly. Tests
are skipped when ``node`` is unavailable on the runner.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = REPO_ROOT / ".github" / "actions" / "ai-agent-runner" / "lib" / "sanitize.mjs"


def _run_node(test_body: str) -> dict:
    """Execute Node code that uses dynamic import to load sanitize.mjs."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node binary not available")
    assert LIB_PATH.exists(), (
        f"sanitize.mjs must exist at {LIB_PATH} so helpers are unit-testable "
        "outside the workflow heredoc"
    )
    # ESM ``import`` requires a static specifier — wrap with dynamic ``import()``.
    script = (
        "const mod = await import(process.env.SANITIZE_PATH);"
        "const {sanitizeForComment, neutralizeMentions, truncateUtf8, toShellSafe} = mod;"
        + test_body
    )
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True,
        env={**os.environ, "SANITIZE_PATH": LIB_PATH.as_uri()},
        check=False,
    )
    assert proc.returncode == 0, (
        f"node exited {proc.returncode}: {proc.stderr.decode('utf-8', errors='replace')}"
    )
    return json.loads(proc.stdout.decode("utf-8"))


def test_base64_round_trip() -> None:
    """``toShellSafe`` must encode and decode to the original UTF-8 bytes."""
    payload = (
        "Line 1 with `backticks` and $vars\n"
        "Line 2 with emoji 🛡️ and quotes 'single' \"double\"\n"
        "Line 3 with @mention and <html>"
    )
    out = _run_node(
        f"const input = {json.dumps(payload)};"
        "const encoded = toShellSafe(input);"
        "const decoded = Buffer.from(encoded, 'base64').toString('utf8');"
        "console.log(JSON.stringify({encoded, decoded, matchesInput: decoded === input}));"
    )
    assert out["matchesInput"] is True
    assert out["decoded"] == payload
    import re
    assert re.fullmatch(r"[A-Za-z0-9+/=]+", out["encoded"])


def test_neutralize_mentions_handles_alternate_encodings() -> None:
    """``neutralizeMentions`` must catch HTML entities, fullwidth, and ZW-prefixed forms."""
    cases = {
        "ascii": "Hello @octocat",
        "fullwidth": "Hello \uff20octocat",
        "html_dec": "Hello &#64;octocat",
        "html_dec_padded": "Hello &#064;octocat",
        "html_hex": "Hello &#x40;octocat",
        "html_hex_padded": "Hello &#x0040;octocat",
        "zwsp_split": "Hello @\u200boctocat",
        "zwj_split": "Hello @\u200doctocat",
    }
    out = _run_node(
        f"const cases = {json.dumps(cases)};"
        "const result = {};"
        "for (const [k, v] of Object.entries(cases)) {"
        "  result[k] = neutralizeMentions(v);"
        "}"
        "console.log(JSON.stringify(result));"
    )
    for key, neutralized in out.items():
        assert "@octocat" not in neutralized, f"{key}: still contains live mention: {neutralized!r}"
        assert "`@`octocat" in neutralized, f"{key}: missing neutralized form: {neutralized!r}"


def test_sanitize_strips_bidi_zero_width_and_osc8() -> None:
    """``sanitizeForComment`` must strip bidi, zero-width, and OSC-8 hyperlinks."""
    cases = {
        "bidi_rlo": "Result: \u202epassed\u202c",
        "bidi_pdi": "Result: \u2068passed\u2069",
        "zwsp": "Hello\u200bworld",
        "zwnj": "Hello\u200cworld",
        "bom": "\ufeffSurprise",
        "osc8_bel": "Click \u001b]8;;https://evil.example.com\u0007here\u001b]8;;\u0007 now",
        "osc8_st": "Click \u001b]8;;https://evil.example.com\u001b\\here\u001b]8;;\u001b\\ now",
        "ansi_csi": "\u001b[31mRED\u001b[0m text",
        "nfkc_workflow_cmd": "\uff1a\uff1aset-output name=x\uff1a\uff1a",
    }
    out = _run_node(
        f"const cases = {json.dumps(cases)};"
        "const result = {};"
        "for (const [k, v] of Object.entries(cases)) {"
        "  result[k] = sanitizeForComment(v);"
        "}"
        "console.log(JSON.stringify(result));"
    )
    for k in ("bidi_rlo", "bidi_pdi"):
        for ch in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"):
            assert ch not in out[k], f"{k}: bidi {ch!r} survived"
    for k in ("zwsp", "zwnj", "bom"):
        for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
            assert ch not in out[k], f"{k}: ZW {ch!r} survived"
    for k in ("osc8_bel", "osc8_st"):
        assert "https://evil.example.com" not in out[k], f"{k}: URL survived: {out[k]!r}"
        assert "\u001b" not in out[k], f"{k}: ESC survived"
    assert "\u001b" not in out["ansi_csi"]
    assert "::set-output" not in out["nfkc_workflow_cmd"], (
        f"NFKC-normalized workflow command survived: {out['nfkc_workflow_cmd']!r}"
    )


def test_response_output_documented_as_comment_only() -> None:
    """Sanity-check the action.yml output declaration documents the constraint."""
    action_yml = (
        REPO_ROOT / ".github" / "actions" / "ai-agent-runner" / "action.yml"
    ).read_text(encoding="utf-8")
    # response output must warn against shell use.
    assert "Do NOT wire this" in action_yml or "Do NOT wire" in action_yml
    assert "response-shell-safe" in action_yml
    # toShellSafe must actually be called in setOutput path.
    assert 'setOutput("response_shell_safe"' in action_yml
