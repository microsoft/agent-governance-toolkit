# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for the AGT Studio Python package."""

import agent_governance_studio


def test_package_import_and_version() -> None:
    assert agent_governance_studio.__version__ == "5.0.0"
