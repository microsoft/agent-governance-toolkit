# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "check_install_scripts.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("check_install_scripts", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_local_workspace_packages_include_unpublished_native_packages() -> None:
    packages = MODULE._local_workspace_packages()

    scripts = packages[
        ("agent-control-specification-linux-x64-gnu", "0.3.1-beta.1")
    ]
    assert scripts == {}


def test_local_workspace_packages_preserve_install_scripts(
    monkeypatch,
) -> None:
    MODULE._local_workspace_packages.cache_clear()
    monkeypatch.setattr(
        MODULE.common,
        "run_git",
        lambda args: "package.json\n",
    )
    monkeypatch.setattr(
        MODULE.common,
        "load_json_at",
        lambda ref, path: {
            "name": "local-package",
            "version": "1.0.0",
            "scripts": {"install": "node install.js", "test": "node test.js"},
        },
    )

    assert MODULE._local_workspace_packages() == {
        ("local-package", "1.0.0"): {"install": "node install.js"}
    }
    MODULE._local_workspace_packages.cache_clear()
