# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for legacy exception constructor compatibility."""

from __future__ import annotations

import pytest

from agent_os.exceptions import PolicyViolationError

CONSTRUCTOR_CASES = [
    ("message_only", ("msg",), {}, "POLICY_VIOLATION", {}),
    ("message_and_code", ("msg", "CUSTOM_CODE"), {}, "CUSTOM_CODE", {}),
    ("message_code_details", ("msg", "CUSTOM", {"k": "v"}), {}, "CUSTOM", {"k": "v"}),
    (
        "keyword_arguments",
        (),
        {"message": "msg", "error_code": "X", "details": {"y": 1}},
        "X",
        {"y": 1},
    ),
]


class TestLegacyConstructors:
    """Verify legacy PolicyViolationError construction remains supported."""

    @pytest.mark.parametrize(
        ("case_name", "args", "kwargs", "expected_code", "expected_details"),
        CONSTRUCTOR_CASES,
        ids=[case[0] for case in CONSTRUCTOR_CASES],
    )
    def test_policy_violation_error_legacy_forms(
        self,
        case_name: str,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        expected_code: str,
        expected_details: dict[str, object],
    ) -> None:
        error = PolicyViolationError(*args, **kwargs)
        data = error.to_dict()

        assert case_name
        assert error.check_result is None
        assert error.error_code == expected_code
        assert error.details == expected_details
        assert data["error"] == expected_code
        assert data["message"] == "msg"
