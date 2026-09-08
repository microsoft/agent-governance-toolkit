# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

from packaging.version import Version


def test_shared_typing_extensions_pin_supports_anyio() -> None:
    requirements = (
        Path(__file__).resolve().parents[2]
        / "agent-governance-python/requirements/ci-test.txt"
    ).read_text(encoding="utf-8")
    pin = next(
        line.split("==", 1)[1].split()[0]
        for line in requirements.splitlines()
        if line.startswith("typing-extensions==")
    )
    assert Version(pin) >= Version("4.16.0")


def test_shared_typing_extensions_exports_runtime_sentinel() -> None:
    from typing_extensions import sentinel

    assert callable(sentinel)
