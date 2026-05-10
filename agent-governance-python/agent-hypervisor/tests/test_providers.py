# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the provider discovery / community-fallback factories.

The fallback imports inside ``hypervisor.providers`` previously
pointed at modules that don't exist in this tree
(``hypervisor.liability.engine`` and ``hypervisor.saga.engine``), so
any caller of ``get_liability_engine`` / ``get_saga_engine`` got an
``ImportError`` when no advanced provider was registered. These tests
exercise the community fallback path against the real public-edition
classes.
"""

from __future__ import annotations

from hypervisor.liability import LiabilityMatrix
from hypervisor.providers import (
    clear_cache,
    get_liability_engine,
    get_saga_engine,
)
from hypervisor.saga.orchestrator import SagaOrchestrator


def setup_function(_func):
    clear_cache()


def test_get_liability_engine_returns_liability_matrix():
    engine = get_liability_engine(session_id="sess-1")
    assert isinstance(engine, LiabilityMatrix)
    assert engine.session_id == "sess-1"


def test_get_saga_engine_returns_saga_orchestrator():
    engine = get_saga_engine()
    assert isinstance(engine, SagaOrchestrator)


def test_get_saga_engine_usable_after_construction():
    """The fallback must produce a usable instance, not just import-clean."""
    engine = get_saga_engine()
    saga = engine.create_saga("session:test")
    assert saga.session_id == "session:test"
