# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for release tooling hardening."""

from __future__ import annotations

import subprocess
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISH = REPO_ROOT / ".github" / "workflows" / "publish.yml"
CONTAINERS = REPO_ROOT / ".github" / "workflows" / "publish-containers.yml"
ESRP_PIPELINE = REPO_ROOT / ".github" / "pipelines" / "esrp-publish.yml"
LOCKFILE = REPO_ROOT / ".github" / "release-tools" / "release-tools.txt"
SRC = REPO_ROOT / ".github" / "release-tools" / "release-tools.in"
ACS_PYTHON_WHEEL_HELPER = REPO_ROOT / "scripts" / "ci" / "build_acs_python_wheel.sh"
ACS_PYTHON_WHEEL_SMOKE = REPO_ROOT / "scripts" / "ci" / "smoke_acs_python_wheel.py"
ACS_PYTHON_DIST_VERIFY = REPO_ROOT / "scripts" / "ci" / "verify_acs_python_dist.py"
PINNED_RUST_INSTALLER = REPO_ROOT / "scripts" / "ci" / "install_pinned_rust.sh"
PINNED_WINDOWS_RUST_INSTALLER = (
    REPO_ROOT / "scripts" / "ci" / "install_pinned_rust_windows.ps1"
)
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


def test_esrp_pipeline_is_restored_as_temporary_registry_publish_path() -> None:
    text = ESRP_PIPELINE.read_text(encoding="utf-8")
    assert "EsrpRelease@11" in text
    assert "dryRun" in text
    assert ".github/release-tools/release-tools.txt" in text
    assert ".github/pipelines/release-tools" not in text


def test_esrp_pipeline_builds_complete_acs_python_distribution() -> None:
    text = ESRP_PIPELINE.read_text(encoding="utf-8")
    # Check the platform / buildPlatform tokens independently so the test stays
    # stable against harmless YAML reindentation of the matrix entries.
    expected_matrix_entries = [
        ("platform: linux-x86_64", "buildPlatform: linux-x86_64"),
        ("platform: linux-aarch64", "buildPlatform: linux-aarch64-cross"),
        ("platform: macos-x86_64", "buildPlatform: macos-x86_64"),
        ("platform: macos-arm64", "buildPlatform: macos-arm64"),
        ("platform: windows-x86_64", "buildPlatform: windows-x86_64"),
    ]
    for platform, build_platform in expected_matrix_entries:
        assert platform in text
        assert build_platform in text

    assert (
        "condition: and(succeeded(), ne('${{ pkg.name }}', 'agent-control-specification'))"
        in text
    )
    assert "python scripts/ci/smoke_acs_python_wheel.py" in text
    assert "python -m maturin build" in text
    assert "bash scripts/ci/install_pinned_rust.sh" in text
    assert "install_pinned_rust_windows.ps1" in text
    assert "pwsh:" in text
    assert "job: Build_PyPI_ACS_sdist" in text
    assert "job: Aggregate_PyPI_ACS" in text
    assert "python scripts/ci/verify_acs_python_dist.py" in text
    assert "Build and smoke test a wheel from the ACS source distribution" in text
    assert "CARGO_NET_OFFLINE=true python -m pip wheel" in text
    assert "grep -Fq 'path = \"../../core\"'" in text
    assert "artifact: 'pypi-agent-control-specification'" in text


def test_publish_workflow_has_no_embedded_esrp_credentials_or_tasks() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    forbidden = [
        "EsrpRelease",
        "ESRP_AAD_ID",
        "ESRP_KEYVAULT_NAME",
        "ESRP_CERT_IDENTIFIER",
        "MICROSOFT_TENANT_ID",
        "ESRPRELPACMAN",
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
    assert 'npm view "${PACKAGE_NAME}@${PACKAGE_VERSION}" version' in text
    assert "already exists on npm, skipping publish" in text
    assert "npm publish ./tgz-output/*.tgz --provenance --access public" in text
    assert "dotnet nuget push ./nupkg/*.nupkg" in text
    assert "Verify package availability in NuGet.org and release provenance" in text


def test_pypi_prepare_and_publish_conditions_match() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    condition = "if: github.event_name == 'workflow_dispatch' && github.event.inputs.dry_run == 'false'"
    python_jobs = [
        text[text.index("publish-acs-python:") : text.index("build-python:")],
        text[text.index("build-python:") : text.index("resolve-npm-matrix:")],
    ]
    for job in python_jobs:
        prepare = job[job.index("- name: Prepare PyPI upload artifacts") :]
        prepare = prepare[: prepare.index("- name: Upload build artifacts")]
        publish = job[job.index("- name: Publish to PyPI") :]
        publish = publish[: publish.index("uses: pypa/gh-action-pypi-publish")]
        assert condition in prepare
        assert condition in publish
    assert (
        "github.event_name == 'workflow_dispatch' && github.event.inputs.dry_run == 'false'"
        in text
    )


def test_acs_python_release_builds_complete_platform_matrix() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    expected_matrix_entries = [
        "ubuntu-24.04, platform: linux-x86_64, target: x86_64-unknown-linux-gnu",
        "ubuntu-24.04-arm, platform: linux-aarch64, target: aarch64-unknown-linux-gnu",
        "macos-15-intel, platform: macos-x86_64, target: x86_64-apple-darwin",
        "macos-15, platform: macos-arm64, target: aarch64-apple-darwin",
        "windows-2022, platform: windows-x86_64, target: x86_64-pc-windows-msvc",
    ]
    for entry in expected_matrix_entries:
        assert entry in text
    assert 'wheel: "*macosx_10_12_x86_64.whl"' in text
    assert 'wheel: "*macosx_11_0_arm64.whl"' in text

    assert "build_any: ${{ steps.resolve.outputs.build_any }}" in text
    assert "acs: ${{ steps.resolve.outputs.acs }}" in text
    assert 'select(.name != "agent-control-specification")' in text
    assert "if: needs.resolve-python-matrix.outputs.build_any == 'true'" in text
    assert text.count("build_acs_python_wheel.sh") == 1
    assert "Verify wheel tag and load native extension" in text
    assert "python scripts/ci/smoke_acs_python_wheel.py" in text
    assert "needs: [resolve-python-matrix, acs-python-wheels, acs-python-sdist]" in text
    assert "Verify complete ACS Python distribution" in text
    assert "python scripts/ci/verify_acs_python_dist.py" in text
    assert "Attest wheel build provenance" in text
    assert "Attest source distribution build provenance" in text
    assert "Build and smoke test a wheel from the source distribution" in text
    assert "CARGO_NET_OFFLINE=true python -m pip wheel" in text
    assert "grep -Fq 'path = \"../../core\"'" in text
    assert "name: pypi-agent-control-specification" in text
    wheel_build = text[
        text.index("acs-python-wheels:") : text.index("acs-python-sdist:")
    ]
    sdist_build = text[
        text.index("acs-python-sdist:") : text.index("publish-acs-python:")
    ]
    acs_publish = text[text.index("publish-acs-python:") : text.index("build-python:")]
    assert "attestations: write" in wheel_build
    assert "attestations: write" in sdist_build
    assert "contents: read" in acs_publish
    assert "attestations: write" not in acs_publish
    # skip-existing keeps re-runs idempotent after a partial upload (matches the sibling leg).
    assert "skip-existing: true" in acs_publish
    # Least-privilege: no publish job should request write access to repo contents.
    assert "contents: write" not in text


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
    assert (
        "github.com/microsoft/agent-governance-toolkit/agent-governance-golang" in names
    )
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
    assert (upload / "demo-0.1.0-py3-none-any.whl").read_text(
        encoding="utf-8"
    ) == "wheel"


def test_container_workflow_uses_owner_derived_registry() -> None:
    text = CONTAINERS.read_text(encoding="utf-8")
    assert "ghcr.io/${{ github.repository_owner }}/agent-governance-toolkit" in text
    assert "ghcr.io/microsoft" not in text
    assert "dry_run:" in text
    assert 'default: "dry-run"' in text
    assert "Build images without pushing tags or attestations to GHCR" in text
    assert (
        "push: ${{ github.event_name == 'release' || github.event.inputs.dry_run == 'false' }}"
        in text
    )
    assert (
        "github.event_name == 'release' || github.event.inputs.dry_run == 'false'"
        in text
    )


def test_acs_python_wheel_helper_uses_pinned_manylinux_build() -> None:
    text = ACS_PYTHON_WHEEL_HELPER.read_text(encoding="utf-8")
    assert "manylinux_2_28_x86_64@sha256:" in text
    assert "manylinux_2_28_aarch64@sha256:" in text
    assert "manylinux_2_28-cross:aarch64@sha256:" in text
    assert "https://static.rust-lang.org/rustup/archive/" in text
    assert "6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d" in text
    assert "1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2" in text
    assert '-e "HOST_UID=$(id -u)"' in text
    assert '-e "HOST_GID=$(id -g)"' in text
    assert 'RUST_TOOLCHAIN="1.89.0"' in text
    assert '--default-toolchain "${RUST_TOOLCHAIN}"' in text
    assert "--require-hashes --no-deps" in text
    assert "--locked" in text
    assert "--compatibility manylinux_2_28" in text
    assert '--target "${RUST_TARGET}"' in text
    assert (
        'chown -R "${HOST_UID}:${HOST_GID}" /work/policy-engine/sdk/python/dist' in text
    )


def test_acs_python_wheel_smoke_rejects_non_wheel(tmp_path: Path) -> None:
    not_a_wheel = tmp_path / "artifact.tar.gz"
    not_a_wheel.write_bytes(b"not a wheel")
    result = subprocess.run(
        [sys.executable, str(ACS_PYTHON_WHEEL_SMOKE), str(not_a_wheel)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode != 0
    assert "expected a wheel path" in result.stderr


def test_pinned_rust_installer_covers_release_hosts() -> None:
    text = PINNED_RUST_INSTALLER.read_text(encoding="utf-8")
    assert 'RUSTUP_VERSION="1.27.1"' in text
    assert 'RUST_TOOLCHAIN="1.89.0"' in text
    assert "6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d" in text
    assert "f547d77c32d50d82b8228899b936bf2b3c72ce0a70fb3b364e7fba8891eba781" in text
    assert "760b18611021deee1a859c345d17200e0087d47f68dfe58278c57abe3a0d3dd0" in text
    assert "193d6c727e18734edbf7303180657e96e9d5a08432002b4e6c5bbe77c60cb3e8" in text
    assert "--retry 5 --retry-all-errors --retry-delay 5" in text
    assert 'if [[ "$ACTUAL_SHA256" != "$RUSTUP_SHA256" ]]' in text
    windows_text = PINNED_WINDOWS_RUST_INSTALLER.read_text(encoding="utf-8")
    assert '[ValidateSet("x86_64-pc-windows-msvc")]' in windows_text
    assert (
        "193d6c727e18734edbf7303180657e96e9d5a08432002b4e6c5bbe77c60cb3e8"
        in windows_text
    )
    assert "Get-FileHash" in windows_text


def test_acs_python_distribution_verifier_rejects_extra_artifact(
    tmp_path: Path,
) -> None:
    version = "0.3.1b1"
    names = [
        f"agent_control_specification-{version}-cp311-abi3-manylinux_2_28_x86_64.whl",
        f"agent_control_specification-{version}-cp311-abi3-manylinux_2_28_aarch64.whl",
        f"agent_control_specification-{version}-cp311-abi3-macosx_10_12_x86_64.whl",
        f"agent_control_specification-{version}-cp311-abi3-macosx_11_0_arm64.whl",
        f"agent_control_specification-{version}-cp311-abi3-win_amd64.whl",
        f"agent_control_specification-{version}.tar.gz",
    ]
    for name in names:
        (tmp_path / name).write_bytes(b"artifact")
    command = [
        sys.executable,
        str(ACS_PYTHON_DIST_VERIFY),
        str(tmp_path),
        "--pyproject",
        str(REPO_ROOT / "policy-engine" / "sdk" / "python" / "pyproject.toml"),
    ]
    valid = subprocess.run(command, capture_output=True, check=False, text=True)
    assert valid.returncode == 0, valid.stderr

    (tmp_path / "unexpected.txt").write_text("extra", encoding="utf-8")
    invalid = subprocess.run(command, capture_output=True, check=False, text=True)
    assert invalid.returncode != 0
    assert "expected exactly six ACS artifacts" in invalid.stderr
