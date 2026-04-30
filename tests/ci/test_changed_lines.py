# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "changed_lines.py"
SPEC = importlib.util.spec_from_file_location("changed_lines", SCRIPT_PATH)
assert SPEC is not None
changed_lines = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(changed_lines)


def test_extract_added_lines_ignores_context_removed_and_file_headers() -> None:
    diff_text = """diff --git a/docs/example.md b/docs/example.md
index 1111111..2222222 100644
--- a/docs/example.md
+++ b/docs/example.md
@@ -1,3 +1,4 @@
 Existing typoo remains in context.
-Removed misspeled text.
+Added misspeled text.
+https://example.invalid/new-link
"""

    assert changed_lines.extract_added_lines(diff_text) == (
        "Added misspeled text.\nhttps://example.invalid/new-link\n"
    )


def test_extract_added_lines_combines_multiple_files_without_diff_metadata() -> None:
    diff_text = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
+New README tokenn.
diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -10 +10,2 @@
+print(\"neew token\")
"""

    assert changed_lines.extract_added_lines(diff_text) == "New README tokenn.\nprint(\"neew token\")\n"


def test_extension_pathspecs_are_normalized_for_git_diff() -> None:
    extensions = changed_lines.normalize_extensions("md,.txt, py,,")

    assert extensions == [".md", ".txt", ".py"]
    assert changed_lines.pathspecs_for_extensions(extensions) == ["*.md", "*.txt", "*.py"]
