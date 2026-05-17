# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for scripts/check_dependency_confusion.py.

Covers the fix for issue #2207: shell-script (.sh/.bash) scanning in
pre-commit mode and false-positive avoidance for echoed/commented
``pip install`` lines.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "check_dependency_confusion.py"
)
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


def test_pre_commit_extension_filter_includes_shell() -> None:
    # Sanity check on the extensions we want to be picked up by pre-commit.
    src = SCRIPT_PATH.read_text(encoding="utf-8")
    assert '".sh"' in src
    assert '".bash"' in src


@pytest.mark.parametrize("ext", [".py", ".md", ".txt", ".ipynb"])
def test_pre_commit_extension_filter_keeps_existing(ext: str) -> None:
    src = SCRIPT_PATH.read_text(encoding="utf-8")
    assert f'"{ext}"' in src
