#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Build and inspect Python wheels that expose the native policy runtime."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
AGT_POLICIES = ROOT / "agent-governance-python" / "agt-policies"
CORE = ROOT / "agent-governance-python" / "agent-governance-toolkit-core"


def _build(package: Path, output: Path) -> Path:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--disable-pip-version-check",
            "--wheel-dir",
            str(output),
            str(package),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    wheels = sorted(output.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel for {package}, found {wheels}")
    return wheels[0]


def _metadata(archive: ZipFile) -> str:
    names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    if len(names) != 1:
        raise RuntimeError(f"expected one METADATA file, found {names}")
    return archive.read(names[0]).decode("utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="agt-native-policy-wheels-") as raw:
        temp = Path(raw)
        agt_wheel = _build(AGT_POLICIES, temp / "agt")
        core_wheel = _build(CORE, temp / "core")

        with ZipFile(agt_wheel) as archive:
            names = set(archive.namelist())
            required = {
                "agt/policies/manifest.py",
                "agt/policies/result.py",
                "agt/policies/runtime.py",
                "agt/policies/session.py",
                "agt/cli/_migrate_bridge.py",
                "agt/cli/_stock_rego/approval.rego",
                "agt/cli/_stock_rego/budgets.rego",
                "agt/cli/_stock_rego/confidence.rego",
                "agt/cli/_stock_rego/patterns.rego",
            }
            missing = sorted(required.difference(names))
            if missing:
                raise RuntimeError(f"agt-policies wheel missing {missing}")
            if any(name.startswith("agt/manifest_resolution/") for name in names):
                raise RuntimeError("agt-policies wheel still exposes manifest_resolution")

        with ZipFile(core_wheel) as archive:
            names = set(archive.namelist())
            if "agent_os/integrations/_native_adapter_runtime.py" not in names:
                raise RuntimeError("core wheel is missing the native adapter runtime")
            metadata = _metadata(archive)
            if "Requires-Dist: agt-policies" not in metadata:
                raise RuntimeError("core wheel does not declare agt-policies")

        print("native policy wheels OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
