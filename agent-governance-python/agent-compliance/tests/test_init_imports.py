# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests that optional-dependency ImportError fallbacks log at DEBUG.

The package supports being imported without ``agent_os`` or
``agentmesh`` installed. The previous code swallowed the resulting
``ImportError`` with ``pass``, leaving no breadcrumb when callers
later wondered why ``StatelessKernel`` was missing. The current code
records each fallback at DEBUG level — these tests pin that contract
without requiring the optional deps to be absent (and without
unloading them where they happen to be installed).
"""

from __future__ import annotations

import importlib
import logging
import sys

import pytest


@pytest.fixture
def reimport_agent_compliance(monkeypatch):
    """Force a fresh import of agent_compliance with controllable state."""
    # Drop any already-loaded entries so the import side effects run again.
    for mod in list(sys.modules):
        if mod == "agent_compliance" or mod.startswith("agent_compliance."):
            sys.modules.pop(mod, None)
    yield
    for mod in list(sys.modules):
        if mod == "agent_compliance" or mod.startswith("agent_compliance."):
            sys.modules.pop(mod, None)


def _force_import_error(monkeypatch, blocked_top_level: set[str]) -> None:
    """Make ``import <name>`` raise ImportError for selected modules."""
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        top = name.split(".", 1)[0]
        if top in blocked_top_level:
            raise ImportError(f"forced absence of {top}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)


def test_missing_agent_os_logs_at_debug(
    monkeypatch, caplog, reimport_agent_compliance
):
    _force_import_error(monkeypatch, {"agent_os"})
    with caplog.at_level(logging.DEBUG, logger="agent_compliance"):
        importlib.import_module("agent_compliance")

    matches = [
        record for record in caplog.records
        if record.name == "agent_compliance"
        and record.levelno == logging.DEBUG
        and "agent_os" in record.getMessage()
    ]
    assert matches, "expected a DEBUG log mentioning agent_os"
    # The breadcrumb must carry the original ImportError text so the
    # operator can distinguish "not installed" from "broken install".
    assert any("forced absence of agent_os" in m.getMessage() for m in matches)


def test_missing_agentmesh_logs_at_debug(
    monkeypatch, caplog, reimport_agent_compliance
):
    _force_import_error(monkeypatch, {"agentmesh"})
    with caplog.at_level(logging.DEBUG, logger="agent_compliance"):
        importlib.import_module("agent_compliance")

    matches = [
        record for record in caplog.records
        if record.name == "agent_compliance"
        and record.levelno == logging.DEBUG
        and "agentmesh" in record.getMessage()
    ]
    assert matches, "expected a DEBUG log mentioning agentmesh"


def test_default_log_level_stays_quiet(
    monkeypatch, caplog, reimport_agent_compliance
):
    # At WARNING (default for most apps) the fallback should not surface
    # — DEBUG is the explicit opt-in for diagnostics.
    _force_import_error(monkeypatch, {"agent_os", "agentmesh"})
    with caplog.at_level(logging.WARNING, logger="agent_compliance"):
        importlib.import_module("agent_compliance")

    noisy = [
        record for record in caplog.records
        if record.name == "agent_compliance"
        and record.levelno >= logging.WARNING
    ]
    assert not noisy, f"unexpected warning/error logs: {noisy!r}"


def test_import_still_succeeds_without_optional_deps(
    monkeypatch, reimport_agent_compliance
):
    _force_import_error(monkeypatch, {"agent_os", "agentmesh"})
    mod = importlib.import_module("agent_compliance")
    # Core exports remain available even when both companion packages
    # are missing.
    assert hasattr(mod, "PromptDefenseEvaluator")
    assert hasattr(mod, "SupplyChainGuard")
