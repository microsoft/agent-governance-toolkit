# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for release tooling hardening.

The canonical AGT release path is GitHub Actions. Azure DevOps ESRP, Microsoft
tenant IDs, Key Vault variables, and Microsoft signing certificates must not be
required to publish canonical artifacts.
"""

from __future__ import annotations

import subprocess
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISH = REPO_ROOT / ".github" / "workflows" / "publish.yml"
CONTAINERS = REPO_ROOT / ".github" / "workflows" / "publish-containers.yml"
LOCKFILE = REPO_ROOT / ".github" / "release-tools" / "release-tools.txt"
SRC = REPO_ROOT / ".github" / "release-tools" / "release-tools.in"
ACS_PYTHON_WHEEL_HELPER = REPO_ROOT / "scripts" / "ci" / "build_acs_python_wheel.sh"
RELEASE_MANIFEST = REPO_ROOT / "scripts" / "ci" / "generate_release_manifest.py"


def test_release_tools_lockfile_exists_and_pins_hashes() -> None:
    assert LOCKFILE.exists(), (
        f"Expected release-tools lockfile at {LOCKFILE} so pip can be invoked "
        "with --require-hashes"
    )
    text = LOCKFILE.read_text(encoding="utf-8")
    entries = [
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert entries, "release-tools.txt has no entries"
    assert text.count("--hash=sha256:") >= 2, (
        "release-tools.txt must include --hash=sha256: pins for release build tools"
    )


def test_release_tools_source_committed() -> None:
    assert SRC.exists(), (
        f"Expected release-tools source spec at {SRC} to document how the "
        "lockfile is regenerated"
    )


def test_publish_workflow_uses_hashed_release_tools() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "--require-hashes" in text
    assert "--no-deps" in text
    assert ".github/release-tools/release-tools.txt" in text


def test_publish_workflow_has_no_esrp_release_path() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    forbidden = [
        "EsrpRelease",
        "ESRP_AAD_ID",
        "ESRP_KEYVAULT_NAME",
        "ESRP_CERT_IDENTIFIER",
        "MICROSOFT_TENANT_ID",
        "ESRPRELPACMAN",
        ".github/pipelines/esrp-publish.yml",
        "CertificateFingerprint",
    ]
    for marker in forbidden:
        assert marker not in text


def test_publish_workflow_publishes_language_artifacts() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "dry_run:" in text
    assert "release-manifest" in text
    assert "pypa/gh-action-pypi-publish" in text
    assert "Prepare PyPI upload artifacts" in text
    assert "shopt -s nullglob" in text
    assert "artifacts=(dist/*.whl dist/*.tar.gz)" in text
    assert 'if [ "${#artifacts[@]}" -eq 0 ]; then' in text
    assert 'cp "${artifacts[@]}" pypi-upload/' in text
    assert "packages-dir: ${{ matrix.path }}/pypi-upload/" in text
    assert "packages-dir: ${{ matrix.path }}/dist/" not in text
    assert 'registry-url: "https://registry.npmjs.org"' in text
    assert "NPM_TOKEN not set, skipping npm publish" in text
    assert "npm view \"${PACKAGE_NAME}@${PACKAGE_VERSION}\" version" in text
    assert "already exists on npm, skipping publish" in text
    assert "npm publish ./tgz-output/*.tgz --provenance --access public" in text
    assert "dotnet nuget push ./nupkg/*.nupkg" in text
    assert "Verify package availability in NuGet.org and release provenance" in text


def test_pypi_prepare_and_publish_conditions_match() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    prepare = text[text.index("- name: Prepare PyPI upload artifacts") :]
    prepare = prepare[: prepare.index("- name: Upload build artifacts")]
    publish = text[text.index("- name: Publish to PyPI") :]
    publish = publish[: publish.index("uses: pypa/gh-action-pypi-publish")]
    condition = "if: github.event_name == 'release' || github.event.inputs.dry_run == 'false'"
    assert condition in prepare
    assert condition in publish
    assert "github.event.inputs.dry_run == 'false'" in text


def test_release_manifest_generator_covers_artifact_families(tmp_path: Path) -> None:
    output = tmp_path / "release-manifest.json"
    subprocess.run(
        [
            "python",
            str(RELEASE_MANIFEST),
            "--event-name",
            "workflow_dispatch",
            "--ref-name",
            "main",
            "--package",
            "all",
            "--dry-run",
            "true",
            "--output",
            str(output),
        ],
        check=True,
        cwd=REPO_ROOT,
    )
    manifest = json.loads(output.read_text(encoding="utf-8"))
    ecosystems = {artifact["ecosystem"] for artifact in manifest["artifacts"]}
    assert {"pypi", "npm", "nuget", "crates.io", "go", "oci"} <= ecosystems
    names = {artifact["name"] for artifact in manifest["artifacts"]}
    assert "agent-governance-toolkit-core" in names
    assert "agent-control-specification-native-packages" in names
    assert "AgentControlSpecification" in names
    assert "agentmesh" in names
    assert "github.com/microsoft/agent-governance-toolkit/agent-governance-golang" in names
    assert "governance-sidecar" in names
    automation = {artifact["automation"] for artifact in manifest["artifacts"]}
    assert automation <= set(manifest["automation_legend"])
    assert "github-actions" in automation
    assert "policy-engine-ci-pack-only" in automation
    assert "manual-publish-needed" in automation
    assert manifest["dry_run"] is True


def test_pypi_upload_artifact_copy_allows_wheel_only(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    upload = tmp_path / "pypi-upload"
    dist.mkdir()
    (dist / "demo-0.1.0-py3-none-any.whl").write_text("wheel", encoding="utf-8")
    script = """
set -euo pipefail
rm -rf pypi-upload
mkdir -p pypi-upload
shopt -s nullglob
artifacts=(dist/*.whl dist/*.tar.gz)
if [ "${#artifacts[@]}" -eq 0 ]; then
  exit 1
fi
cp "${artifacts[@]}" pypi-upload/
"""
    subprocess.run(["bash", "-c", script], cwd=tmp_path, check=True)
    assert (upload / "demo-0.1.0-py3-none-any.whl").read_text(encoding="utf-8") == "wheel"


def test_container_workflow_uses_owner_derived_registry() -> None:
    text = CONTAINERS.read_text(encoding="utf-8")
    assert "ghcr.io/${{ github.repository_owner }}/agent-governance-toolkit" in text
    assert "ghcr.io/microsoft" not in text
    assert "dry_run:" in text
    assert 'default: "dry-run"' in text
    assert "Build images without pushing tags or attestations to GHCR" in text
    assert "push: ${{ github.event_name == 'release' || github.event.inputs.dry_run == 'false' }}" in text
    assert "github.event_name == 'release' || github.event.inputs.dry_run == 'false'" in text


def test_acs_python_wheel_helper_uses_pinned_manylinux_build() -> None:
    text = ACS_PYTHON_WHEEL_HELPER.read_text(encoding="utf-8")
    assert "manylinux_2_28_x86_64@sha256:" in text
    assert "https://static.rust-lang.org/rustup/archive/" in text
    assert "6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d" in text
    assert 'RUST_TOOLCHAIN="1.89.0"' in text
    assert '--default-toolchain "${RUST_TOOLCHAIN}"' in text
    assert "--require-hashes --no-deps" in text
    assert "--compatibility manylinux_2_28" in text
