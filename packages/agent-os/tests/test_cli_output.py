# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from agent_os.policies.cli import success,error,warn,policy_violation,passed_check

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


def test_policy_violation(capsys):
    policy_violation("Policy violation detected!")
    captured = capsys.readouterr()
    assert "policy violation" in captured.out.lower()


def test_passed_check(capsys):
    passed_check("Test passed successfully!")
    captured = capsys.readouterr()
    assert "test passed" in captured.out.lower()
