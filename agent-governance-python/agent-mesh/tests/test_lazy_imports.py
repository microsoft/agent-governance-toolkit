# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agentmesh/__init__.py's lazy attribute loading (#3923).

`agentmesh/__init__.py` used to import every layer (client, identity,
trust, reward, telemetry) eagerly at module level. Python always runs
this file before any submodule import completes, so even `import
agentmesh.governance` - which only needs the governance package's own
code - paid the full cost of all of them: ~3.5s cold, dominated by
`agentmesh.identity`'s httpx-based external JWKS federation code
pulled in transitively through `agentmesh.client`.

Each name in `agentmesh.__all__` is now resolved from its owning
submodule on first access via a PEP 562 module `__getattr__`, so
`agentmesh.identity`/`.trust`/`.reward`/`.client`/`.telemetry` are
only imported if something actually touches a name that lives there.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import agentmesh


def _run_and_list_modules(import_statement: str) -> set[str]:
    """Run `import_statement` in a fresh interpreter and return every
    module under `agentmesh` that ended up in sys.modules.

    A subprocess is required: this test process may already have any
    of these submodules cached from other tests importing them, which
    would hide a regression.
    """
    code = (
        f"{import_statement}\n"
        "import sys\n"
        "print('\\n'.join(m for m in sys.modules if m == 'agentmesh' or m.startswith('agentmesh.')))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        cwd=None,
    )
    return set(result.stdout.split())


class TestLazyTopLevelImport:
    """`import agentmesh.governance` must not drag in the other layers."""

    def test_importing_governance_does_not_load_identity(self):
        loaded = _run_and_list_modules("import agentmesh.governance")
        heavy = {m for m in loaded if m.startswith("agentmesh.identity")}
        assert not heavy, f"importing agentmesh.governance pulled in: {heavy}"

    def test_importing_governance_does_not_load_client_trust_reward_or_telemetry(self):
        loaded = _run_and_list_modules("import agentmesh.governance")
        unexpected = {
            m
            for m in loaded
            if m.split(".")[:2]
            in (
                ["agentmesh", "client"],
                ["agentmesh", "trust"],
                ["agentmesh", "reward"],
                ["agentmesh", "telemetry"],
            )
        }
        assert not unexpected, f"importing agentmesh.governance pulled in: {unexpected}"

    def test_from_governance_import_govern_stays_lazy(self):
        loaded = _run_and_list_modules("from agentmesh.governance import govern")
        heavy = {
            m
            for m in loaded
            if m.startswith(
                ("agentmesh.identity", "agentmesh.client", "agentmesh.trust", "agentmesh.reward")
            )
        }
        assert not heavy, f"from agentmesh.governance import govern pulled in: {heavy}"


class TestLazyAttributeAccessCorrectness:
    """Every documented name must still resolve to the right object."""

    @pytest.mark.parametrize("name", [n for n in agentmesh.__all__ if n != "__version__"])
    def test_every_public_name_resolves(self, name):
        value = getattr(agentmesh, name)
        assert value is not None

    def test_client_still_works_through_lazy_access(self):
        """Accessing the heaviest lazy name (AgentMeshClient) still works -
        this is the "pay the cost on first real access instead of at
        import time" contract, not a removal."""
        loaded = _run_and_list_modules("import agentmesh; agentmesh.AgentMeshClient")
        assert "agentmesh.client" in loaded
        assert "agentmesh.identity" in loaded

    def test_unknown_attribute_raises_attribute_error(self):
        with pytest.raises(AttributeError, match="has no attribute 'NotARealAttribute'"):
            agentmesh.NotARealAttribute

    def test_repeated_access_returns_the_same_object(self):
        """First access resolves and caches; second access must not
        re-trigger __getattr__ (and must return the identical object,
        not a fresh re-import)."""
        first = agentmesh.PolicyEngine
        second = agentmesh.PolicyEngine
        assert first is second

    def test_dir_includes_lazy_names(self):
        exported = set(dir(agentmesh))
        for name in agentmesh.__all__:
            if name != "__version__":
                assert name in exported


class TestLazySubmoduleAttributeParity:
    """On main, `import agentmesh` then `agentmesh.identity` (etc.) worked
    as a side effect of the eager `from .<submodule> import (...)` statements -
    any submodule import binds the submodule itself onto its parent
    package. That must keep working even though those imports are gone."""

    @pytest.mark.parametrize(
        "submodule_name",
        [
            "client",
            "exceptions",
            "governance",
            "identity",
            "reward",
            "telemetry",
            "trust",
            "trust_types",
        ],
    )
    def test_submodule_attribute_resolves_to_the_submodule(self, submodule_name):
        import importlib

        value = getattr(agentmesh, submodule_name)
        assert value is importlib.import_module(f"agentmesh.{submodule_name}")

    def test_dir_includes_submodule_names(self):
        exported = set(dir(agentmesh))
        for submodule_name in ("client", "identity", "trust", "reward", "telemetry"):
            assert submodule_name in exported
