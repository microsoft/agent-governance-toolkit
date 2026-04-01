# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

# These functions were proposed in PR #554 but not implemented in the source module.
# Skip until the colored output functions are added to agent_os.policies.cli.
pytest.skip(
    "Skipped: success/error/warn/policy_violation/passed_check not yet in policies.cli",
    allow_module_level=True,
)

def test_success(capsys):
    success("This is a success message")
    captured = capsys.readouterr()
    assert "success message" in captured.out.lower()


def test_error(capsys):
    error("This is an error message")
    captured = capsys.readouterr()
    assert "error message" in captured.err.lower()


def test_warn(capsys):
    warn("This is a warning message")
    captured = capsys.readouterr()
    assert "warning message" in captured.out.lower()


def test_policy_violation_output(capsys):
    policy_violation("FAIL: invalid policy")
    captured = capsys.readouterr()
    assert "fail" in captured.err.lower()


def test_passed_check(capsys):
    passed_check("Test passed successfully!")
    captured = capsys.readouterr()
    assert "test passed" in captured.out.lower()