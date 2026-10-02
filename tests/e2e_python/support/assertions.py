# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared assertion helpers reused by the per-scenario tests."""

from __future__ import annotations

from pathlib import Path

from .models import ScenarioResult

# Fake secrets embedded in fixtures; must never leak into artifacts.
RAW_SECRETS = (
    "123-45-6789",
    "person@example.test",
    "sk-1234567890abcdefghijkl",
    # Underscore-glued form: a secret annotated _old must be redacted too
    # (regression for issue #3933). The fixture in test_pii_redaction.py
    # feeds this value through MuteAgent.scrub_text so the assertion is
    # exercised — do not add values here without a corresponding fixture.
    "AKIAIOSFODNN7EXAMPLE_old",
)


def assert_exercised(result: ScenarioResult) -> None:
    assert result.participation_status == "exercised", (
        "Model did not produce the action required to exercise this scenario"
    )


def assert_no_raw_secrets(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    for secret in RAW_SECRETS:
        assert secret not in content
