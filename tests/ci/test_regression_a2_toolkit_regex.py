# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for red-team finding A2.

Original regex accepted PEP 440 post-releases (``3.7.0.post1``), dev releases
(``3.7.0.dev1``), and local-version identifiers (``3.7.0+evil``) through the
trailing ``([.+-][A-Za-z0-9._+-]+)?`` alternation. Pip resolves these to
different artifacts than the canonical release, so a regex pass did not
guarantee the canonical version was installed.

Tightened spec: ``^[0-9]+\\.[0-9]+\\.[0-9]+((a|b|rc)[0-9]+)?$`` -- only the
final release plus optional ``a``/``b``/``rc`` pre-release suffix.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

ACTIONS = [
    REPO_ROOT / "action" / "action.yml",
]

READMES = [
    REPO_ROOT / "action" / "README.md",
]

EXPECTED_REGEX = "^[0-9]+\\.[0-9]+\\.[0-9]+((a|b|rc)[0-9]+)?$"
FORBIDDEN_FRAGMENT = "[.+-][A-Za-z0-9._+-]+"


@pytest.mark.parametrize("action_path", ACTIONS, ids=lambda p: p.parent.name + "/" + p.name)
def test_a2_toolkit_version_regex_is_tight(action_path: Path) -> None:
    text = action_path.read_text(encoding="utf-8")
    assert EXPECTED_REGEX in text, (
        f"{action_path} does not contain the tightened toolkit-version regex; "
        f"expected literal {EXPECTED_REGEX!r}"
    )
    assert FORBIDDEN_FRAGMENT not in text, (
        f"{action_path} still accepts PEP 440 post/dev/local-version suffixes "
        f"via {FORBIDDEN_FRAGMENT!r}"
    )


@pytest.mark.parametrize("action_path", ACTIONS, ids=lambda p: p.parent.name + "/" + p.name)
def test_a2_action_yaml_parses(action_path: Path) -> None:
    # Defensive: regex tightening shouldn't break YAML parsing.
    yaml.safe_load(action_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("readme_path", READMES, ids=lambda p: p.parent.name)
def test_a2_readme_documents_accepted_version_syntax(readme_path: Path) -> None:
    text = readme_path.read_text(encoding="utf-8")
    assert "Accepted version syntax" in text, (
        f"{readme_path} must document the accepted version syntax for "
        "toolkit-version after the A2 tightening"
    )
