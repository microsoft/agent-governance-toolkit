# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for scripts/check_dependency_confusion.py.

Covers the fix for issue #2207: shell-script (.sh/.bash) scanning in
pre-commit mode and false-positive avoidance for echoed/commented
``pip install`` lines.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "check_dependency_confusion.py"
)
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("check_dep_conf", SCRIPT_PATH)
assert SPEC is not None
check_dep_conf = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_dep_conf)


def _write(tmp_path: Path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_sh_real_pip_install_unregistered_is_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        "#!/usr/bin/env bash\nset -e\npip install totally-not-a-real-package-xyz\n",
    )
    findings = check_dep_conf.check_file(path)
    assert any("totally-not-a-real-package-xyz" in f for f in findings), findings


def test_sh_echoed_pip_install_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        '#!/usr/bin/env bash\necho "pip install totally-not-a-real-package-xyz"\n',
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_printf_pip_install_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        '#!/usr/bin/env bash\nprintf "run: pip install totally-not-a-real-package-xyz\\n"\n',
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_commented_pip_install_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        "#!/usr/bin/env bash\n# pip install totally-not-a-real-package-xyz\n",
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_inline_comment_pip_install_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        "#!/usr/bin/env bash\ntrue  # pip install totally-not-a-real-package-xyz\n",
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_known_package_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        "#!/usr/bin/env bash\npip install pydantic\n",
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_editable_path_install_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "build.sh",
        "#!/usr/bin/env bash\npip install --no-cache-dir -e agent-governance-python/agt-policies\n",
    )
    assert check_dep_conf.check_file(path) == []


def test_python_printed_pip_install_text_is_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "workflow.yml",
        "run: |\n  python - <<'PY'\n  print('OK: pip install packages are registered')\n  PY\n",
    )
    assert check_dep_conf.check_file(path) == []


def test_sh_real_install_after_echo_separator_is_flagged(tmp_path: Path) -> None:
    # Regression: `echo ...; pip install <unregistered>` is a real install.
    path = _write(
        tmp_path,
        "build.sh",
        '#!/usr/bin/env bash\necho preparing; pip install totally-not-a-real-package-xyz\n',
    )
    findings = check_dep_conf.check_file(path)
    assert any("totally-not-a-real-package-xyz" in f for f in findings), findings


def test_md_pip_install_after_hash_still_flagged(tmp_path: Path) -> None:
    # Suppression must not affect non-shell files: a markdown heading like
    # `# Install: pip install <unregistered>` should still be flagged.
    path = _write(
        tmp_path,
        "guide.md",
        "# Install: pip install totally-not-a-real-package-xyz\n",
    )
    findings = check_dep_conf.check_file(path)
    assert any("totally-not-a-real-package-xyz" in f for f in findings), findings


def test_txt_existing_behavior_unchanged_flags_unregistered(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "install.txt",
        "Run: pip install totally-not-a-real-package-xyz\n",
    )
    findings = check_dep_conf.check_file(path)
    assert any("totally-not-a-real-package-xyz" in f for f in findings), findings


def test_md_existing_behavior_unchanged_known_package_ok(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "README.md",
        "# Install\n\n```bash\npip install pydantic\n```\n",
    )
    assert check_dep_conf.check_file(path) == []


@pytest.mark.parametrize(
    "package",
    ["agent-governance-toolkit-compliance", "agent_governance_toolkit_compliance"],
)
@pytest.mark.parametrize(
    "specifier",
    ["==5.0.0", ">=5.0.0,<5.1.0", "[full]>=5.0.0,<5.1.0; python_version >= '3.11'"],
)
def test_registered_compliance_requirements_are_accepted(
    tmp_path: Path, package: str, specifier: str,
) -> None:
    path = _write(tmp_path, "requirements.txt", f"{package}{specifier}\n")

    assert check_dep_conf.check_requirements_file(path) == []


@pytest.mark.parametrize(
    "package",
    ["agent-governance-toolkit-compliance", "agent_governance_toolkit_compliance"],
)
@pytest.mark.parametrize("command", ["pip install", "python -m pip install"])
@pytest.mark.parametrize("specifier", ["", "==5.0.0", ">=5.0.0,<5.1.0"])
def test_registered_compliance_pip_commands_are_accepted(
    tmp_path: Path, package: str, command: str, specifier: str,
) -> None:
    path = _write(tmp_path, "build.sh", f"{command} {package}{specifier}\n")

    assert package in check_dep_conf.REGISTERED_PACKAGES
    assert check_dep_conf.extract_package_names(package) == [package]
    assert check_dep_conf.check_file(path) == []


@pytest.mark.parametrize(
    "package",
    [
        "agent-governance-toolkit-compliance".replace("ia", "ai"),
        "agent_governance_toolkit_compliance".replace("ia", "ai"),
        "agent-governance-toolkit-compliance-unregistered",
        "agent_governance_toolkit_compliance_unregistered",
    ],
)
@pytest.mark.parametrize("surface", ["requirements", "pip"])
def test_unregistered_compliance_lookalikes_are_flagged(
    tmp_path: Path, package: str, surface: str,
) -> None:
    if surface == "requirements":
        path = _write(tmp_path, "requirements.txt", f"{package}>=5.0.0,<5.1.0\n")
        findings = check_dep_conf.check_requirements_file(path)
    else:
        path = _write(tmp_path, "build.sh", f"pip install {package}\n")
        findings = check_dep_conf.check_file(path)

    assert len(findings) == 1
    assert f"'{package}' may not be registered on PyPI" in findings[0]


@pytest.mark.parametrize(
    "package",
    ["agent-governance-toolkit-compliance", "agent_governance_toolkit_compliance"],
)
def test_strict_scan_accepts_registered_compliance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, package: str,
) -> None:
    _write(tmp_path, "requirements.txt", f"{package}==5.0.0\n")
    _write(
        tmp_path, "pyproject.toml",
        f'[project]\ndependencies = ["{package}>=5.0.0,<5.1.0"]\n',
    )
    path = _write(tmp_path, "build.sh", f"pip install {package}\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--strict", path])

    assert check_dep_conf.main() == 0


@pytest.mark.parametrize(
    "package",
    ["agent-governance-toolkit-compliance".replace("ia", "ai"), "agent_governance_toolkit_compliance_unregistered"],
)
@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("requirements.txt", "{package}==5.0.0\n"),
        ("pyproject.toml", '[project]\ndependencies = ["{package}>=5.0.0,<5.1.0"]\n'),
        ("build.sh", "pip install {package}\n"),
    ],
)
def test_strict_scan_rejects_unregistered_compliance_lookalikes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], package: str, filename: str, content: str,
) -> None:
    path = _write(tmp_path, filename, content.format(package=package))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--strict", path])

    assert check_dep_conf.main() == 1
    output = capsys.readouterr().out
    assert f"'{package}' may not be registered on PyPI" in output
    assert output.count("may not be registered on PyPI") == 1


def test_pre_commit_extension_filter_includes_shell() -> None:
    # Sanity check on the extensions we want to be picked up by pre-commit.
    src = SCRIPT_PATH.read_text(encoding="utf-8")
    assert '".sh"' in src
    assert '".bash"' in src


@pytest.mark.parametrize("ext", [".py", ".md", ".txt", ".ipynb"])
def test_pre_commit_extension_filter_keeps_existing(ext: str) -> None:
    src = SCRIPT_PATH.read_text(encoding="utf-8")
    assert f'"{ext}"' in src


@pytest.mark.parametrize(
    "section",
    ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"],
)
def test_registered_vite_is_accepted_in_npm_dependencies(
    tmp_path: Path, section: str,
) -> None:
    path = _write(
        tmp_path, "package.json", json.dumps({section: {"vite": "8.0.16"}}),
    )

    assert check_dep_conf.check_package_json(path) == []


@pytest.mark.parametrize(
    "section",
    ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"],
)
@pytest.mark.parametrize("package", ["vite-unregistered", "totally-not-a-real-package-xyz"])
def test_unregistered_npm_names_are_still_flagged(
    tmp_path: Path, section: str, package: str,
) -> None:
    path = _write(
        tmp_path, "package.json", json.dumps({section: {package: "8.0.16"}}),
    )

    findings = check_dep_conf.check_package_json(path)

    assert len(findings) == 1
    assert f"npm '{package}' ({section}) may not be registered" in findings[0]
