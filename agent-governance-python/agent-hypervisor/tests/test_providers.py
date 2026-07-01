# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for provider discovery / community-fallback factories."""

from __future__ import annotations

from hypervisor.providers import (
    clear_cache,
    get_saga_engine,
)
from hypervisor.saga.orchestrator import SagaOrchestrator


def setup_function(_func):
    clear_cache()


def test_get_saga_engine_returns_saga_orchestrator():
    engine = get_saga_engine()
    assert isinstance(engine, SagaOrchestrator)


def test_get_saga_engine_usable_after_construction():
    """The fallback must produce a usable instance, not just import-clean."""
    engine = get_saga_engine()
    saga = engine.create_saga("session:test")
    assert saga.session_id == "session:test"
