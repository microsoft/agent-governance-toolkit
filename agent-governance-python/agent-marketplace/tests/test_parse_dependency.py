# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for ``_parse_dependency``.

Regression coverage for the PEP 508 parser used during dependency
resolution. Previously the parser scanned for operators in a fixed order
and split at the first match, mis-handling compound specifiers like
``>=1.0,<2.0`` (parsed as ``(name, "1.0,<2.0")``) and never recognising
``!=`` / ``~=``.
"""

from __future__ import annotations

import pytest

from agent_marketplace.installer import _parse_dependency
from agent_marketplace.manifest import MarketplaceError


class TestParseDependency:
    def test_no_specifier_returns_none_version(self):
        assert _parse_dependency("plugin-name") == ("plugin-name", None)

    def test_exact_pin_returns_version_string(self):
        assert _parse_dependency("plugin-name==1.2.3") == ("plugin-name", "1.2.3")

    def test_lower_bound_only_returns_none_version(self):
        # `>=1.0` is a range, not a pin; registry should resolve latest.
        assert _parse_dependency("plugin-name>=1.0") == ("plugin-name", None)

    def test_compound_specifier_returns_none_version(self):
        # Regression: previously parsed as ("plugin-name", "1.0,<2.0").
        assert _parse_dependency("plugin-name>=1.0,<2.0") == ("plugin-name", None)

    def test_compound_with_exact_pin_returns_pin(self):
        # `==X` always wins over surrounding range bounds.
        assert _parse_dependency("plugin-name>=1.0,==1.5") == ("plugin-name", "1.5")

    def test_inequality_returns_none_version(self):
        # Regression: previously fell through and returned ("plugin-name!=1.0", None).
        assert _parse_dependency("plugin-name!=1.0") == ("plugin-name", None)

    def test_compatible_release_returns_none_version(self):
        # Regression: previously fell through and returned ("plugin-name~=1.0", None).
        assert _parse_dependency("plugin-name~=1.0") == ("plugin-name", None)

    def test_whitespace_around_operator(self):
        assert _parse_dependency("plugin-name == 1.2.3") == ("plugin-name", "1.2.3")

    def test_invalid_specifier_raises(self):
        with pytest.raises(MarketplaceError, match="Invalid dependency"):
            _parse_dependency("not a valid spec!!!")
