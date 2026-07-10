# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :mod:`agt.cli.migrate` — the ``agt migrate v4-to-v5`` CLI.

The suite covers the algorithm contract from ``plan.md`` §5 / M6.S1:

- v4 artefact discovery (governance.yaml chains, GovernancePolicy calls,
  PolicyAction.BLOCK references, CedarBackend calls, PolicyInterceptor
  subclasses, legacy ``agent_os.policies`` imports);
- dry-run safety (no file mutation);
- ``--write`` side effects (manifest.yaml + Rego bundle + .v4-backup);
- bridge-output schema validity for the GovernancePolicy materialisation
  path;
- Markdown structural correctness of the rendered report.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import pytest
import yaml

from agt.cli import migrate as migrate_mod
from agt.policies import AgtManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_governance(path: Path, rule_name: str = "deny_dangerous_tool") -> None:
    doc = {
        "rules": [
            {
                "name": rule_name,
                "condition": {
                    "field": "tool_call.name",
                    "operator": "eq",
                    "value": "rm",
                },
                "action": "deny",
                "priority": 10,
                "message": "rm is blocked",
            }
        ],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _write_source(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")


def _md_headings(text: str) -> list[str]:
    return [line for line in text.splitlines() if re.match(r"^#{1,6} ", line)]


# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------


def test_find_governance_in_project_tree(tmp_path: Path) -> None:
    """The migrator discovers governance.yaml everywhere under the root."""
    root_gov = tmp_path / "governance.yaml"
    _write_governance(root_gov)
    nested_dir = tmp_path / "svc" / "billing"
    nested_dir.mkdir(parents=True)
    _write_governance(nested_dir / "governance.yaml", rule_name="deny_wire")

    report = migrate_mod.migrate_project(tmp_path, write=False)

    chain_roots = {gc.chain_root for gc in report.governance_chains}
    assert tmp_path.resolve() in chain_roots
    assert nested_dir.resolve() in chain_roots
    assert all(gc.error is None for gc in report.governance_chains)


def test_skips_well_known_junk_directories(tmp_path: Path) -> None:
    """The walk MUST prune .venv, node_modules, .git etc."""
    _write_governance(tmp_path / "governance.yaml")
    for junk in (".venv", "node_modules", ".git", "__pycache__"):
        junk_dir = tmp_path / junk / "deep"
        junk_dir.mkdir(parents=True)
        _write_governance(junk_dir / "governance.yaml")

    report = migrate_mod.migrate_project(tmp_path, write=False)

    chain_roots = {gc.chain_root for gc in report.governance_chains}
    for junk in (".venv", "node_modules", ".git", "__pycache__"):
        assert all(junk not in p.parts for p in chain_roots), chain_roots


def test_finds_governance_policy_constructor(tmp_path: Path) -> None:
    """The AST scanner picks up every GovernancePolicy(...) call."""
    src = tmp_path / "app.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy, PatternType

policy = GovernancePolicy(
    name="strict",
    max_tokens=2048,
    max_tool_calls=3,
    allowed_tools=["lookup", "fetch"],
    blocked_patterns=["password"],
    require_human_approval=True,
    confidence_threshold=0.85,
)
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert len(report.governance_policies) == 1
    gp = report.governance_policies[0]
    assert gp.location.path == src
    assert gp.kwargs["name"] == "strict"
    assert gp.kwargs["max_tokens"] == 2048
    assert gp.kwargs["allowed_tools"] == ["lookup", "fetch"]
    # The snippet that the report shows MUST include the
    # GovernancePolicy literal so users can diff old vs new.
    assert "GovernancePolicy" in gp.rewrite_snippet


def test_finds_aliased_governance_policy_constructor(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    _write_source(
        src,
        "from agent_os.integrations.base import GovernancePolicy as GP\n"
        "policy = GP(max_tokens=2048)\n",
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert len(report.governance_policies) == 1
    assert report.governance_policies[0].migration_kwargs["max_tokens"] == 2048


def test_finds_policy_action_block_references(tmp_path: Path) -> None:
    """PolicyAction.BLOCK references are recorded with location + rewrite."""
    src = tmp_path / "policy_use.py"
    _write_source(
        src,
        """
from agent_os.policies import PolicyAction, PolicyRule

rule = PolicyRule(
    name="x", condition={"field": "a", "operator": "eq", "value": 1},
    action=PolicyAction.BLOCK,
)
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert len(report.policy_action_blocks) == 1
    pb = report.policy_action_blocks[0]
    assert pb.location.path == src
    # The rewrite snippet maps BLOCK → "deny" per AGT-DELTA D-M3.S4.
    assert "\"deny\"" in pb.rewrite_snippet
    assert "BLOCK" in pb.rewrite_snippet


def test_finds_cedar_backend_calls(tmp_path: Path) -> None:
    """add_backend(CedarBackend(...)) is detected with a v5 yaml hint."""
    src = tmp_path / "cedar_wire.py"
    _write_source(
        src,
        """
from agent_os.policies.cedar import CedarBackend

registry.add_backend(CedarBackend(policy_file="my.cedar"))
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert len(report.cedar_backends) == 1
    cb = report.cedar_backends[0]
    assert cb.location.path == src
    assert "type: cedar" in cb.rewrite_snippet
    assert "policy_path:" in cb.rewrite_snippet
    assert "bundle:" not in cb.rewrite_snippet
    assert "CedarBackend" in cb.rewrite_snippet


def test_finds_direct_policy_interceptor_subclasses(tmp_path: Path) -> None:
    """Classes that inherit from PolicyInterceptor are flagged for manual review."""
    src = tmp_path / "interceptors.py"
    _write_source(
        src,
        """
from agent_os.policies import PolicyInterceptor

class MyInterceptor(PolicyInterceptor):
    def before_tool(self, ctx, name, args):
        return None

class NotAnInterceptor:
    pass
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    interceptor_names = {pi.class_name for pi in report.policy_interceptors}
    assert "MyInterceptor" in interceptor_names
    assert "NotAnInterceptor" not in interceptor_names


def test_finds_legacy_agent_os_imports(tmp_path: Path) -> None:
    """Every ``from agent_os.policies import …`` is recorded."""
    src = tmp_path / "uses_legacy.py"
    _write_source(
        src,
        """
from agent_os.policies import PolicyAction, PolicyRule
from agent_os.policies.evaluator import PolicyEvaluator
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    paths = {li.location.path for li in report.legacy_imports}
    assert src in paths
    names = sorted(
        n for li in report.legacy_imports if li.location.path == src for n in li.imported_names
    )
    assert "PolicyAction" in names
    assert "PolicyEvaluator" in names


# ---------------------------------------------------------------------------
# Dry-run vs --write behaviour
# ---------------------------------------------------------------------------


def test_dry_run_does_not_touch_project_files(tmp_path: Path) -> None:
    """Default mode is dry-run and MUST be side-effect free."""
    gov = tmp_path / "governance.yaml"
    _write_governance(gov)
    src = tmp_path / "app.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy(name="default")
""".strip(),
    )

    pre_files = sorted(p.name for p in tmp_path.iterdir())
    report = migrate_mod.migrate_project(tmp_path, write=False)
    post_files = sorted(p.name for p in tmp_path.iterdir())

    assert pre_files == post_files
    # No manifest.yaml, no policy/ directory, no .v4-backup in dry-run.
    assert not (tmp_path / "manifest.yaml").exists()
    assert not (tmp_path / "policy").exists()
    assert not (tmp_path / ".governance.yaml.v4-backup").exists()
    # The report still records what would have happened.
    assert report.governance_chains
    assert report.governance_policies


def test_write_produces_v5_artifacts(tmp_path: Path) -> None:
    """``--write`` materialises manifest.yaml + Rego bundle on disk."""
    gov = tmp_path / "governance.yaml"
    _write_governance(gov)

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.governance_chains
    manifest_path = tmp_path / "manifest.yaml"
    assert manifest_path.is_file()
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert data["extends"] == []
    assert "agt_legacy_rules" in data["policies"]
    bundle_dir = Path(data["policies"]["agt_legacy_rules"]["bundle"])
    assert bundle_dir.is_dir()
    assert (bundle_dir / "agt_legacy.rego").is_file()


def test_write_backs_up_governance_yaml(tmp_path: Path) -> None:
    """The original governance.yaml gets moved to .governance.yaml.v4-backup."""
    gov = tmp_path / "governance.yaml"
    _write_governance(gov)
    original = gov.read_text(encoding="utf-8")

    migrate_mod.migrate_project(tmp_path, write=True)

    assert not gov.exists()
    backup = tmp_path / ".governance.yaml.v4-backup"
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("existing_name", ["manifest.yaml", "policy"])
def test_governance_chain_never_overwrites_existing_output(
    tmp_path: Path, existing_name: str
) -> None:
    governance = tmp_path / "governance.yaml"
    _write_governance(governance)
    existing = tmp_path / existing_name
    if existing_name == "policy":
        existing.mkdir()
        sentinel = existing / "sentinel"
    else:
        sentinel = existing
    sentinel.write_text("keep", encoding="utf-8")

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.governance_chains[0].error is not None
    assert "refusing to overwrite" in report.governance_chains[0].error
    assert governance.is_file()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_governance_chain_never_overwrites_existing_backup(
    tmp_path: Path,
) -> None:
    governance = tmp_path / "governance.yaml"
    _write_governance(governance)
    backup = tmp_path / ".governance.yaml.v4-backup"
    backup.write_text("keep", encoding="utf-8")

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.governance_chains[0].error is not None
    assert "backup already exists" in report.governance_chains[0].error
    assert governance.is_file()
    assert backup.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "manifest.yaml").exists()
    assert not (tmp_path / "policy").exists()


def test_write_governance_policy_creates_manifest_per_source(tmp_path: Path) -> None:
    """A GovernancePolicy() call produces policies/<basename>.manifest.yaml."""
    src = tmp_path / "billing_bot.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy

policy = GovernancePolicy(
    name="billing",
    max_tokens=1024,
    max_tool_calls=2,
    allowed_tools=["lookup"],
)
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)
    assert report.governance_policies

    out = tmp_path / "policies" / "billing_bot.manifest.yaml"
    assert out.is_file()
    data = yaml.safe_load(out.read_text(encoding="utf-8"))

    # The bridge output MUST validate against the AGT-MANIFEST-1.0 shape
    # (version string, empty extends, every binding policy_id is declared,
    # bundle directory exists on disk).
    assert data["agent_control_specification_version"].endswith("-agt")
    assert data["extends"] == []
    assert data["intervention_points"], "manifest needs at least one binding"
    declared = set(data["policies"].keys())
    for binding in data["intervention_points"].values():
        assert binding["policy"]["id"] in declared
    bundle = Path(data["policies"]["billing_bot"]["bundle"])
    assert bundle.is_dir()
    assert (bundle / "billing_bot.rego").is_file()
    assert AgtManifest.from_path(out).to_document() == data


def test_governance_policy_defaults_are_migrated_exactly(tmp_path: Path) -> None:
    src = tmp_path / "default_bot.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy()
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)

    finding = report.governance_policies[0]
    assert finding.manual_review == []
    assert finding.manifest_path is not None
    manifest = AgtManifest.from_path(finding.manifest_path)
    policy = manifest.policies["default_bot"]
    rego = (Path(policy.bundle) / "default_bot.rego").read_text(
        encoding="utf-8"
    )
    assert '"token_count": 4096' in rego
    assert '"tool_call_count": 10' in rego
    assert "deny_if_low_confidence(0.8)" in rego


def test_pattern_types_are_preserved_in_generated_rego(tmp_path: Path) -> None:
    src = tmp_path / "patterns.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy, PatternType
policy = GovernancePolicy(
    blocked_patterns=[
        ("secret-[0-9]+", PatternType.REGEX),
        ("*.exe", PatternType.GLOB),
    ],
)
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)

    finding = report.governance_policies[0]
    assert finding.manual_review == []
    manifest = AgtManifest.from_path(finding.manifest_path)
    rego = Path(manifest.policies["patterns"].bundle, "patterns.rego").read_text(
        encoding="utf-8"
    )
    assert "secret-[0-9]+" in rego
    assert json.dumps(r"(?s:.*\.exe)\z") in rego


@pytest.mark.parametrize(
    "argument, expected",
    [
        ("max_tokens=get_limit()", "dynamic expression"),
        (
            'blocked_patterns=[("x", PatternType.UNKNOWN)]',
            "unsupported PatternType.UNKNOWN",
        ),
        (
            'blocked_patterns=[("(", PatternType.REGEX)]',
            ("not valid Go RE2", "OPA is required"),
        ),
        (
            r'blocked_patterns=[("(a)\\1", PatternType.REGEX)]',
            ("not valid Go RE2", "OPA is required"),
        ),
        ("timeout_seconds=30", "host configuration"),
        ("**settings", "**kwargs expansion"),
    ],
)
def test_ambiguous_policy_constructor_refuses_write(
    tmp_path: Path, argument: str, expected: str | tuple[str, ...]
) -> None:
    src = tmp_path / "ambiguous.py"
    _write_source(
        src,
        (
            "from agent_os.integrations.base import GovernancePolicy, PatternType\n"
            f"policy = GovernancePolicy({argument})\n"
        ),
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)

    finding = report.governance_policies[0]
    expected_fragments = (expected,) if isinstance(expected, str) else expected
    assert any(
        fragment in reason
        for reason in finding.manual_review
        for fragment in expected_fragments
    )
    assert finding.manifest_path is None
    assert not (tmp_path / "policies" / "ambiguous.manifest.yaml").exists()
    assert "Manual review required" in finding.rewrite_snippet


def test_existing_outputs_are_never_overwritten(tmp_path: Path) -> None:
    src = tmp_path / "bot.py"
    _write_source(
        src,
        "from agent_os.integrations.base import GovernancePolicy\n"
        "policy = GovernancePolicy()\n",
    )
    output = tmp_path / "policies" / "bot.manifest.yaml"
    output.parent.mkdir()
    output.write_text("sentinel", encoding="utf-8")

    report = migrate_mod.migrate_project(tmp_path, write=True)

    finding = report.governance_policies[0]
    assert finding.manifest_path is None
    assert any("refusing to overwrite" in reason for reason in finding.manual_review)
    assert output.read_text(encoding="utf-8") == "sentinel"


def test_multiple_policies_in_one_source_refuse_partial_write(
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path / "bots.py",
        "from agent_os.integrations.base import GovernancePolicy\n"
        "reader = GovernancePolicy(name='reader')\n"
        "writer = GovernancePolicy(name='writer')\n",
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert len(report.governance_policies) == 2
    assert all(finding.manual_review for finding in report.governance_policies)
    assert all(
        finding.manifest_path is None
        for finding in report.governance_policies
    )
    assert not (tmp_path / "policies").exists()


def test_manual_review_blocks_all_project_writes(tmp_path: Path) -> None:
    governance = tmp_path / "governance.yaml"
    _write_governance(governance)
    _write_source(
        tmp_path / "app.py",
        "from agent_os.integrations.base import GovernancePolicy\n"
        "policy = GovernancePolicy(max_tokens=get_limit())\n",
    )

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.requires_manual_review()
    assert governance.is_file()
    assert not (tmp_path / "manifest.yaml").exists()
    assert not (tmp_path / ".governance.yaml.v4-backup").exists()


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def test_render_report_is_valid_markdown(tmp_path: Path) -> None:
    """The Markdown report parses cleanly into headings + tables.

    We do not pull in a Markdown library; instead we assert structural
    invariants (heading hierarchy, table separators) that any compliant
    renderer relies on.
    """
    _write_governance(tmp_path / "governance.yaml")
    _write_source(
        tmp_path / "app.py",
        """
from agent_os.integrations.base import GovernancePolicy
from agent_os.policies import PolicyAction, PolicyInterceptor
from agent_os.policies.cedar import CedarBackend

policy = GovernancePolicy(name="x", max_tokens=1024)
action = PolicyAction.BLOCK
registry.add_backend(CedarBackend(policy_file="my.cedar"))

class MyInterceptor(PolicyInterceptor):
    pass
""".strip(),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)
    text = migrate_mod.render_report(report)

    headings = _md_headings(text)
    assert headings[0] == "# AGT v4 → v5 Migration Report"
    titles = " | ".join(headings)
    for required in (
        "1. Governance chains",
        "2. `GovernancePolicy(...)` constructor calls",
        "3. `PolicyAction.BLOCK` references",
        "4. `CedarBackend(...)` calls",
        "5. Direct `PolicyInterceptor` subclasses",
        "6. Legacy `agent_os.policies` imports",
    ):
        assert required in titles

    # Every Markdown table we emit MUST have the alignment row right
    # below the header. Find one and check that the next line is the
    # ``|---|`` separator.
    lines = text.splitlines()
    for idx, line in enumerate(lines[:-1]):
        if line.startswith("| # ") and " | " in line:
            sep = lines[idx + 1]
            assert sep.startswith("|---|"), sep


def test_dry_run_handles_empty_project(tmp_path: Path) -> None:
    """A v5-clean project produces a no-findings report and no crash."""
    report = migrate_mod.migrate_project(tmp_path, write=False)
    assert not report.has_findings()
    text = migrate_mod.render_report(report)
    assert "No v4 artifacts detected" in text


def test_unparseable_python_is_reported_not_silently_skipped(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken.py").write_text(
        "from agent_os.integrations.base import GovernancePolicy\n"
        "policy = GovernancePolicy(\n",
        encoding="utf-8",
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert report.errors
    assert "cannot parse Python source" in report.errors[0]


# ---------------------------------------------------------------------------
# CLI entry-point smoke
# ---------------------------------------------------------------------------


def test_cli_module_help_lists_migrate_verb() -> None:
    """``python -m agt.cli migrate --help`` runs cleanly."""
    proc = subprocess.run(
        [sys.executable, "-m", "agt.cli", "migrate", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "v4-to-v5" in proc.stdout
    assert "--write" in proc.stdout
    assert "--write-report" in proc.stdout


def test_cli_dry_run_writes_report_to_path(tmp_path: Path) -> None:
    """``--write-report`` writes the Markdown report to disk."""
    _write_governance(tmp_path / "governance.yaml")
    report_path = tmp_path / "MIGRATION.md"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agt.cli",
            "migrate",
            "v4-to-v5",
            str(tmp_path),
            "--write-report",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert report_path.is_file()
    body = report_path.read_text(encoding="utf-8")
    assert "AGT v4 → v5 Migration Report" in body
    # Dry-run MUST NOT have touched the project.
    assert (tmp_path / "governance.yaml").exists()
    assert not (tmp_path / "manifest.yaml").exists()


def test_cli_dry_run_and_write_are_mutually_exclusive(tmp_path: Path) -> None:
    """Passing both ``--write`` and ``--dry-run`` exits non-zero."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agt.cli",
            "migrate",
            "v4-to-v5",
            str(tmp_path),
            "--write",
            "--dry-run",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "mutually exclusive" in proc.stderr


def test_cli_write_exits_nonzero_when_manual_review_is_required(
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path / "app.py",
        "from agent_os.integrations.base import GovernancePolicy\n"
        "policy = GovernancePolicy(max_tokens=get_limit())\n",
    )

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agt.cli",
            "migrate",
            "v4-to-v5",
            str(tmp_path),
            "--write",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1
    assert "Manual review required" in proc.stdout


# ---------------------------------------------------------------------------
# Iteration helpers
# ---------------------------------------------------------------------------


def _iter_paths(paths: Iterable[Path]) -> list[str]:
    return sorted(str(p) for p in paths)


def test_finding_locations_carry_line_numbers(tmp_path: Path) -> None:
    """Every finding records a non-zero line number from the AST."""
    src = tmp_path / "lines.py"
    _write_source(
        src,
        "\n".join(
            [
                "from agent_os.policies import PolicyAction",
                "from agent_os.integrations.base import GovernancePolicy",
                "",
                "policy = GovernancePolicy(name=\"a\")",
                "action = PolicyAction.BLOCK",
            ]
        ),
    )

    report = migrate_mod.migrate_project(tmp_path, write=False)

    assert report.governance_policies[0].location.line >= 1
    assert report.policy_action_blocks[0].location.line >= 1
    assert report.legacy_imports[0].location.line >= 1


# ---------------------------------------------------------------------------
# Sanity: existing 106 tests still pass — verified by the CI matrix
# rather than from inside this file. We only check our own module
# imports cleanly so a broken refactor surfaces immediately.
# ---------------------------------------------------------------------------


def test_module_imports_cleanly() -> None:
    """Importing :mod:`agt.cli.migrate` does not require ``agent_os``."""
    import importlib

    importlib.import_module("agt.cli")
    importlib.import_module("agt.cli.migrate")
    importlib.import_module("agt.cli.__main__")


def test_write_does_not_import_public_runtime_bridge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The one-way migrator is isolated from the runtime compatibility bridge."""
    src = tmp_path / "mod.py"
    _write_source(
        src,
        """
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy(name="x")
""".strip(),
    )

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def fake_import(name, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "agt.policies.bridge":
            raise ImportError("simulated missing bridge")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)

    report = migrate_mod.migrate_project(tmp_path, write=True)
    finding = report.governance_policies[0]
    assert finding.manual_review == []
    assert finding.manifest_path is not None
    assert finding.manifest_path.is_file()
    assert "agt.policies.bridge" not in finding.rewrite_snippet
