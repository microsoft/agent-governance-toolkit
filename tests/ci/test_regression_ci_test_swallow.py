# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for the deferred ``|| true`` swallow on ``ci-test.txt``.

Two install steps in ``.github/workflows/ci.yml`` previously used::

    pip install ... --require-hashes -r ci-test.txt 2>/dev/null || true

The trailing ``|| true`` swallowed every pip failure including hash
mismatches, missing files, and resolver errors. CI then proceeded as if
the install had succeeded, defeating the whole point of ``--require-hashes``.

Fix: replace the swallow with a positive ``[ -f "$CI_TEST_REQS" ]`` guard
so a missing file is benign but an attempted install that fails errors out.
"""

from __future__ import annotations

import re
from pathlib import Path

CI = (
    Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "ci.yml"
)


def test_ci_test_txt_install_has_no_pipe_to_true_swallow() -> None:
    text = CI.read_text(encoding="utf-8")
    lines = text.splitlines()
    # Walk the file. For every line that references ci-test.txt in an
    # install context, look at the same line and the next 2 lines for a
    # `|| true` swallow.
    for idx, line in enumerate(lines):
        if "ci-test.txt" not in line:
            continue
        window = "\n".join(lines[max(0, idx - 1): idx + 3])
        assert not re.search(r"2>/dev/null\s*\|\|\s*true", window), (
            f"ci.yml line {idx+1}: ci-test.txt install must not swallow "
            f"failures via `2>/dev/null || true`. Window:\n{window}"
        )
