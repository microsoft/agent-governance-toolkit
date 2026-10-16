# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the deterministic CI workflow generator.

These tests guard the properties that make generated workflows safe to trust:
determinism, full SHA pinned actions, least privilege permissions, a DO NOT EDIT
banner, and that the committed YAML matches the manifest (no drift). They also
exercise the fail closed validators on malformed manifests.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "scripts" / "ci" / "generate_workflows.py"

USES_RE = re.compile(r"uses:\s+(\S+)")
SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_workflows", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def test_build_outputs_includes_policy_engine_workflow():
    outputs = gen.build_outputs()
    names = {path.name for path in outputs}
    assert "policy-engine-ci.yml" in names


def test_generation_is_deterministic():
    first = gen.build_outputs()
    second = gen.build_outputs()
    assert {p.name: c for p, c in first.items()} == {p.name: c for p, c in second.items()}


def test_every_generated_action_is_sha_pinned():
    for _path, content in gen.build_outputs().items():
        for ref in USES_RE.findall(content):
            assert SHA_PIN_RE.match(ref), f"action not SHA pinned: {ref}"


def test_generated_workflows_have_banner_and_least_privilege():
    for _path, content in gen.build_outputs().items():
        assert content.startswith("# DO NOT EDIT."), "missing generated banner"
        assert "permissions:\n  contents: read\n" in content


def test_generated_opa_downloads_verify_checksum():
    for _path, content in gen.build_outputs().items():
        if "openpolicyagent.org/downloads" in content:
            assert "sha256sum -c -" in content
            assert gen.OPA_LINUX_AMD64_SHA256 in content
            assert "--retry 5 --retry-all-errors --retry-delay 5 --connect-timeout 20" in content


def test_policy_engine_python_job_uses_pinned_tooling():
    content = gen.build_outputs()[REPO_ROOT / ".github" / "workflows" / "policy-engine-ci.yml"]
    assert "python -m pip install --upgrade pip==24.3.1" in content
    assert "pip install maturin==1.8.7" in content
    assert "pip install build==1.2.1" in content
    assert "pip install setuptools==80.9.0" in content
    assert "pytest==9.0.3" in content
    assert "pip install ./sdk/python ./generator pytest" not in content


def test_policy_engine_workflow_packages_acs_artifacts():
    content = gen.build_outputs()[REPO_ROOT / ".github" / "workflows" / "policy-engine-ci.yml"]
    assert "cargo package -p agent_control_specification_core --allow-dirty" in content
    assert "cargo package -p agent_control_specification --allow-dirty" not in content
    assert "bash ../scripts/ci/build_acs_python_wheel.sh .." in content
    assert "python -m build --no-isolation ./generator" in content
    assert "npm pack --pack-destination" in content
    assert "node scripts/package-native.mjs --package agent-control-specification-linux-x64-gnu" in content
    assert "agent-control-specification-linux-x64-gnu-0.3.1-beta.0.tgz" in content
    assert "dotnet build AgentControlSpecification.sln --configuration Release" in content
    assert "AgentControlSpecificationAllowIncompleteNativePack=true" in content


def test_committed_yaml_matches_manifest():
    # The committed workflow must equal the freshly rendered output, i.e. the
    # same invariant the CI --check job enforces.
    drift = []
    for path, content in gen.build_outputs().items():
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            drift.append(str(path.relative_to(REPO_ROOT)))
    assert not drift, f"committed workflows drift from manifest: {drift}. Run --write."


def test_check_mode_passes_on_committed_tree():
    assert gen.main(["--check"]) == 0


def test_check_mode_detects_composite_action_pin_drift(tmp_path, monkeypatch, capsys):
    action_dir = tmp_path / "stale-action"
    action_dir.mkdir()
    (action_dir / "action.yml").write_text(
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/setup-python@0000000000000000000000000000000000000000 # v0.0.0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", tmp_path)

    assert gen.main(["--check"]) == 1
    captured = capsys.readouterr()
    assert "stale-action" in captured.err
    assert "actions/setup-python" in captured.err


def test_write_mode_syncs_composite_action_pins(tmp_path, monkeypatch):
    action_dir = tmp_path / "stale-action"
    action_dir.mkdir()
    action_file = action_dir / "action.yaml"
    action_file.write_text(
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/checkout@0000000000000000000000000000000000000000 # v0.0.0\n"
        "      with:\n"
        "        fetch-depth: 0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", tmp_path)
    monkeypatch.setattr(gen, "build_outputs", lambda *_args: {})
    actions = gen._load_actions(gen.ACTIONS_PATH)

    assert gen.main(["--write"]) == 0
    rewritten = action_file.read_text(encoding="utf-8")
    assert f"uses: {actions['checkout']}\n" in rewritten
    assert "with:\n        fetch-depth: 0\n" in rewritten


def test_unregistered_composite_action_reference_fails_closed(tmp_path, monkeypatch):
    action_dir = tmp_path / "unknown-action"
    action_dir.mkdir()
    action_file = action_dir / "action.yml"
    original = (
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/checkout@0000000000000000000000000000000000000000 # v0.0.0\n"
        "    - uses: unregistered/action@0000000000000000000000000000000000000000\n"
    )
    action_file.write_text(original, encoding="utf-8")
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", tmp_path)
    actions = gen._load_actions(gen.ACTIONS_PATH)

    issues = gen.check_composite_action_pins(actions)
    assert any("unregistered/action" in issue for issue in issues)
    with pytest.raises(gen.GenerationError, match="not registered"):
        gen.sync_composite_action_pins(actions)
    assert action_file.read_text(encoding="utf-8") == original


def test_unpinned_action_is_rejected(tmp_path):
    bad = tmp_path / "actions.toml"
    bad.write_text('[checkout]\nuses = "actions/checkout@v4"\ncomment = "v4"\n', encoding="utf-8")
    with pytest.raises(gen.GenerationError):
        gen._load_actions(bad)


def test_output_outside_workflows_dir_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": "elsewhere/x.yml",
        "job": [{"id": "a", "step": [{"name": "n", "run": "echo hi"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)


def test_unknown_toolchain_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": ".github/workflows/x.yml",
        "job": [{"id": "a", "toolchains": ["haskell"], "step": [{"name": "n", "run": "echo hi"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)


def test_sync_registry_adopts_a_bumped_pin(tmp_path, monkeypatch):
    # A Dependabot-shaped bump: the generated workflow carries a new SHA and
    # version comment, the registry still has the old pin. Sync adopts it.
    new_sha = "a" * 40
    registry = tmp_path / "actions.toml"
    registry.write_text(
        f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n',
        encoding="utf-8",
    )
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        "jobs:\n  x:\n    steps:\n"
        f"      - uses: actions/checkout@{new_sha} # v7.1.0\n",
        encoding="utf-8",
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    assert gen.sync_registry_from_tree(verify=False) == ["checkout"]
    updated = registry.read_text(encoding="utf-8")
    assert f'uses = "actions/checkout@{new_sha}"' in updated
    assert 'comment = "v7.1.0"' in updated


def test_sync_registry_is_a_noop_when_already_in_sync(tmp_path, monkeypatch):
    sha = "c" * 40
    registry = tmp_path / "actions.toml"
    registry.write_text(
        f'[checkout]\nuses = "actions/checkout@{sha}"\ncomment = "v7.1.0"\n',
        encoding="utf-8",
    )
    original = registry.read_text(encoding="utf-8")
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        f"      - uses: actions/checkout@{sha} # v7.1.0\n", encoding="utf-8"
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    assert gen.sync_registry_from_tree() == []
    assert registry.read_text(encoding="utf-8") == original


def test_sync_registry_fails_closed_on_conflicting_pins(tmp_path, monkeypatch):
    registry = tmp_path / "actions.toml"
    registry.write_text(
        f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n',
        encoding="utf-8",
    )
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        f"      - uses: actions/checkout@{'a' * 40} # v7.1.0\n", encoding="utf-8"
    )
    composite = tmp_path / "composite"
    action_dir = composite / "x"
    action_dir.mkdir(parents=True)
    (action_dir / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n"
        f"    - uses: actions/checkout@{'d' * 40} # v7.2.0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    with pytest.raises(gen.GenerationError, match="conflicting pins"):
        gen.sync_registry_from_tree()


def test_sync_registry_refuses_unsafe_comment(tmp_path, monkeypatch):
    # A version comment that could break out of the TOML string is refused,
    # not embedded, so a crafted managed file cannot corrupt actions.toml.
    registry = tmp_path / "actions.toml"
    original = f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n'
    registry.write_text(original, encoding="utf-8")
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        f'      - uses: actions/checkout@{"a" * 40} # v1" evil = "x\n',
        encoding="utf-8",
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    with pytest.raises(gen.GenerationError, match="unsafe version comment"):
        gen.sync_registry_from_tree()
    assert registry.read_text(encoding="utf-8") == original


def test_sync_registry_preserves_registry_layout_and_comments(tmp_path, monkeypatch):
    # Only the bumped entry changes; header comments, blank lines, and the other
    # entries are left byte for byte intact.
    registry = tmp_path / "actions.toml"
    registry.write_text(
        "# header comment\n\n"
        f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n\n'
        f'[setup-node]\nuses = "actions/setup-node@{"e" * 40}"\ncomment = "v7.0.0"\n',
        encoding="utf-8",
    )
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        f"      - uses: actions/checkout@{'a' * 40} # v7.1.0\n"
        f"      - uses: actions/setup-node@{'e' * 40} # v7.0.0\n",
        encoding="utf-8",
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    assert gen.sync_registry_from_tree(verify=False) == ["checkout"]
    text = registry.read_text(encoding="utf-8")
    assert text.startswith("# header comment\n\n")
    assert f'actions/setup-node@{"e" * 40}' in text
    assert 'comment = "v7.0.0"' in text
    assert f'actions/checkout@{"a" * 40}' in text


def test_sync_registry_refuses_symlinked_registry_path(tmp_path, monkeypatch):
    # A symlinked actions.toml must not be written through.
    real = tmp_path / "real_actions.toml"
    real.write_text(
        f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n',
        encoding="utf-8",
    )
    link = tmp_path / "actions.toml"
    link.symlink_to(real)
    generated = tmp_path / "policy-engine-ci.yml"
    generated.write_text(
        f"      - uses: actions/checkout@{'a' * 40} # v7.1.0\n", encoding="utf-8"
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", link)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(
        gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")}
    )

    with pytest.raises(gen.GenerationError, match="symlink"):
        gen.sync_registry_from_tree()
    assert real.read_text(encoding="utf-8").count("b" * 40) == 1


def test_intra_repo_symlinked_composite_file_is_rejected(tmp_path, monkeypatch):
    # A symlinked action file is refused even when it resolves to another file
    # inside the composite directory.
    composite = tmp_path / "composite"
    (composite / "real").mkdir(parents=True)
    target = composite / "real" / "action.yml"
    target.write_text("runs:\n  using: composite\n  steps: []\n", encoding="utf-8")
    (composite / "linky").mkdir()
    (composite / "linky" / "action.yml").symlink_to(target)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)

    with pytest.raises(gen.GenerationError, match="symlink"):
        gen._composite_action_files()


def test_symlinked_composite_actions_dir_is_rejected(tmp_path, monkeypatch):
    real_dir = tmp_path / "real_actions_dir"
    real_dir.mkdir()
    link = tmp_path / "composite"
    link.symlink_to(real_dir, target_is_directory=True)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", link)

    with pytest.raises(gen.GenerationError, match="symlink"):
        gen._composite_action_files()


def test_composite_action_symlink_escape_is_rejected(tmp_path, monkeypatch):
    # A composite action that is a symlink out of the actions directory is
    # refused, so neither the reader nor the writer follows it out of the tree.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n"
        f"    - uses: actions/checkout@{'a' * 40} # v1.0.0\n",
        encoding="utf-8",
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    (composite / "evil").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)

    with pytest.raises(gen.GenerationError, match="escapes"):
        gen._composite_action_files()


def test_build_outputs_rejects_output_path_traversal(monkeypatch):
    actions = gen._load_actions(gen.ACTIONS_PATH)
    evil = {
        "workflow": [
            {
                "id": "x",
                "name": "x",
                "output": ".github/workflows/../../../tmp/escape.yml",
                "job": [{"id": "a", "step": [{"name": "n", "run": "echo hi"}]}],
            }
        ]
    }
    monkeypatch.setattr(gen, "_load_toml", lambda _p: evil)
    with pytest.raises(gen.GenerationError, match="escapes the repository"):
        gen.build_outputs(actions)


def test_pin_line_regex_ignores_commented_uses():
    # A commented-out step is not a pin source (anchored regex).
    assert gen._PIN_LINE_RE.match("      # - uses: actions/checkout@" + "a" * 40 + " # v9.9.9") is None
    assert gen._PIN_LINE_RE.match("      - uses: actions/checkout@" + "a" * 40 + " # v7.0.1") is not None
    assert gen._PIN_LINE_RE.match("        uses: actions/setup-python@" + "b" * 40 + " # v7.0.0") is not None


def test_sync_ignores_commented_pin_but_adopts_real_one(tmp_path, monkeypatch):
    registry = tmp_path / "actions.toml"
    registry.write_text(
        f'[checkout]\nuses = "actions/checkout@{"b" * 40}"\ncomment = "v7.0.1"\n',
        encoding="utf-8",
    )
    generated = tmp_path / "policy-engine-ci.yml"
    # A commented-out bogus bump plus the real pin that matches the registry.
    generated.write_text(
        f"      # - uses: actions/checkout@{'f' * 40} # v9.9.9\n"
        f"      - uses: actions/checkout@{'b' * 40} # v7.0.1\n",
        encoding="utf-8",
    )
    composite = tmp_path / "composite"
    composite.mkdir()
    monkeypatch.setattr(gen, "ACTIONS_PATH", registry)
    monkeypatch.setattr(gen, "COMPOSITE_ACTIONS_DIR", composite)
    monkeypatch.setattr(gen, "build_outputs", lambda *_a: {generated: generated.read_text("utf-8")})
    # The commented bogus line is ignored, so no update and no conflict.
    assert gen.sync_registry_from_tree(verify=False) == []


def test_verify_pin_versions_accepts_matching_sha(monkeypatch):
    monkeypatch.setattr(gen, "_resolve_tag_commit_sha", lambda name, ver, *, token: "a" * 40)
    gen.verify_pin_versions({"checkout": ("actions/checkout@" + "a" * 40, "v7.1.0")}, token=None)


def test_verify_pin_versions_rejects_mismatch(monkeypatch):
    monkeypatch.setattr(gen, "_resolve_tag_commit_sha", lambda name, ver, *, token: "c" * 40)
    with pytest.raises(gen.GenerationError, match="pin mismatch"):
        gen.verify_pin_versions({"checkout": ("actions/checkout@" + "a" * 40, "v7.1.0")}, token=None)


def test_verify_pin_versions_fails_closed_when_unresolvable(monkeypatch):
    monkeypatch.setattr(gen, "_resolve_tag_commit_sha", lambda name, ver, *, token: None)
    with pytest.raises(gen.GenerationError, match="cannot verify"):
        gen.verify_pin_versions({"checkout": ("actions/checkout@" + "a" * 40, "v9.9.9")}, token=None)


def test_verify_pin_versions_skips_non_version_comment(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("resolver must not be called for a non-version comment")

    monkeypatch.setattr(gen, "_resolve_tag_commit_sha", _boom)
    gen.verify_pin_versions(
        {"rust-toolchain": ("dtolnay/rust-toolchain@" + "a" * 40, "stable")}, token=None
    )


def test_unknown_action_key_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": ".github/workflows/x.yml",
        "job": [{"id": "a", "toolchains": ["python"], "step": [{"name": "n", "uses": "missing-action"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)
