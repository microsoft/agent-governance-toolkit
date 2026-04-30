# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[2] / "scripts" / "extract_workflow_shell.py"
SPEC = importlib.util.spec_from_file_location("extract_workflow_shell", SCRIPT_PATH)
assert SPEC is not None
extract_workflow_shell = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(extract_workflow_shell)

emit_shell = extract_workflow_shell.emit_shell
extract_file = extract_workflow_shell.extract_file
workflow_files = extract_workflow_shell.workflow_files

FIXTURES = Path(__file__).parent / "fixtures"


def test_workflow_files_finds_yml_files() -> None:
    files = workflow_files(FIXTURES)

    assert files == [FIXTURES / "workflow.yml"]


def test_extract_file_includes_default_and_explicit_bash() -> None:
    blocks = extract_file(FIXTURES / "workflow.yml")

    assert len(blocks) == 2
    assert blocks[0][1] == 14
    assert blocks[0][2] == [
        'echo "default"',
        "python3 - <<'PY'",
        'print("nested")',
        "PY",
    ]
    assert blocks[1][2] == ['echo "explicit"']


def test_emit_shell_adds_source_headers_and_skips_non_bash() -> None:
    output = emit_shell(FIXTURES)

    assert f"# === {(FIXTURES / 'workflow.yml').as_posix()}:14 ===" in output
    assert 'echo "default"' in output
    assert 'echo "explicit"' in output
    assert "Write-Output" not in output
    assert output.endswith("\n")
