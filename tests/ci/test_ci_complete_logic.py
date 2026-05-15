# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci_complete_check.py"


def run_check(needs: dict[str, dict[str, str]]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(needs),
        text=True,
        capture_output=True,
        check=False,
    )


def test_all_success_outputs_empty_and_exits_zero() -> None:
    result = run_check({"lint": {"result": "success"}, "test": {"result": "success"}})

    assert result.returncode == 0
    assert result.stdout == "\n"
    assert result.stderr == ""


def test_one_failure_outputs_name_and_exits_one() -> None:
    result = run_check({"lint": {"result": "success"}, "test": {"result": "failure"}})

    assert result.returncode == 1
    assert result.stdout == "test\n"
    assert result.stderr == ""


def test_multiple_failures_are_comma_joined_in_order() -> None:
    result = run_check(
        {
            "lint": {"result": "failure"},
            "test": {"result": "success"},
            "build-pypi": {"result": "timed_out"},
        }
    )

    assert result.returncode == 1
    assert result.stdout == "lint,build-pypi\n"
    assert result.stderr == ""


def test_cancelled_counts_as_failed() -> None:
    result = run_check({"security": {"result": "cancelled"}})

    assert result.returncode == 1
    assert result.stdout == "security\n"
    assert result.stderr == ""


def test_success_with_skipped_outputs_empty_and_exits_zero() -> None:
    result = run_check(
        {"changes": {"result": "success"}, "lint": {"result": "skipped"}}
    )

    assert result.returncode == 0
    assert result.stdout == "\n"
    assert result.stderr == ""
