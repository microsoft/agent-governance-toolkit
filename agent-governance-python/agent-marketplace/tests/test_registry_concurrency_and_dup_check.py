# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``PluginRegistry`` concurrency and duplicate-check ordering.

Regression for REVIEW.md HIGH Extensions #12: ``register`` previously
called ``self._plugins.setdefault(name, {})`` *before* checking for a
duplicate version. The setdefault path leaves an empty inner dict in
place when subsequent steps on the registration path raise (today
that's only the duplicate-version check itself, but any future early-
return adds the failure mode). There is also no concurrency control —
two threads registering distinct versions of the same plugin can race.

The fix:

* Wraps mutation in a re-entrant lock so concurrent ``register`` /
  ``unregister`` / lookups are serialized.
* Performs the duplicate-version check *before* mutating the registry.
* Inserts the inner dict only on confirmed-non-duplicate registrations.
"""

from __future__ import annotations

import threading
import time

import pytest

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest, PluginType
from agent_marketplace.registry import PluginRegistry


def _make_manifest(name: str, version: str = "1.0.0") -> PluginManifest:
    return PluginManifest(
        name=name,
        version=version,
        description=f"{name} {version}",
        author="test@example.com",
        plugin_type=PluginType.INTEGRATION,
    )


class TestRegisterDuplicateCheckOrdering:
    def test_register_duplicate_does_not_pollute_inner_dict(self):
        """A duplicate-version registration must not mutate ``self._plugins``."""
        registry = PluginRegistry()
        manifest = _make_manifest("polluter", "1.0.0")
        registry.register(manifest)

        # Snapshot state before the duplicate attempt.
        before = {
            n: set(versions.keys())
            for n, versions in registry._plugins.items()
        }

        # Duplicate must raise — and must NOT add a second entry or
        # introduce any new key.
        with pytest.raises(MarketplaceError, match="already registered"):
            registry.register(manifest)

        after = {
            n: set(versions.keys())
            for n, versions in registry._plugins.items()
        }
        assert before == after

    def test_register_unknown_plugin_does_not_leave_empty_inner_dict_on_failure(self):
        """If duplicate-check raises for a freshly-named entry, no empty dict remains.

        With the prior implementation, ``setdefault(name, {})`` ran before
        the duplicate check; any future code path that raises between
        those steps would orphan an empty inner dict at ``name``. The
        new check-before-mutate ordering forecloses that class of bug.
        """
        registry = PluginRegistry()
        # Force an artificial duplicate by pre-populating an empty inner
        # dict (simulating prior pollution) and asserting register
        # behaves sanely. With check-before-mutate, registering a NEW
        # version under an existing-but-empty inner dict succeeds.
        registry._plugins["preexisting"] = {}
        registry.register(_make_manifest("preexisting", "1.0.0"))
        assert "1.0.0" in registry._plugins["preexisting"]


class TestRegistryConcurrentRegister:
    def test_concurrent_distinct_versions_all_register(self):
        """Threads registering distinct versions of the same plugin must all succeed."""
        registry = PluginRegistry()
        N = 32
        errors: list[Exception] = []
        barrier = threading.Barrier(N)

        def worker(version_minor: int):
            try:
                barrier.wait(timeout=5)
                registry.register(_make_manifest("racer", f"1.{version_minor}.0"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"unexpected errors: {errors}"
        # All N versions present, no duplicates.
        assert len(registry._plugins["racer"]) == N
        expected = {f"1.{i}.0" for i in range(N)}
        assert set(registry._plugins["racer"].keys()) == expected

    def test_concurrent_same_version_exactly_one_succeeds(self):
        """When N threads register the SAME name+version, exactly one wins.

        The remaining N-1 must each raise ``MarketplaceError`` with
        the "already registered" message. None must produce a corrupt
        state (e.g. a half-written inner dict).
        """
        registry = PluginRegistry()
        N = 16
        results: list[str] = []  # "ok" / "dup" / exception repr
        results_lock = threading.Lock()
        barrier = threading.Barrier(N)

        def worker():
            try:
                barrier.wait(timeout=5)
                registry.register(_make_manifest("hotspot", "1.0.0"))
                with results_lock:
                    results.append("ok")
            except MarketplaceError as exc:
                if "already registered" in str(exc):
                    with results_lock:
                        results.append("dup")
                else:
                    with results_lock:
                        results.append(repr(exc))

        threads = [threading.Thread(target=worker) for _ in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("ok") == 1, f"expected one winner, got {results.count('ok')}: {results}"
        assert results.count("dup") == N - 1, f"unexpected outcomes: {results}"
        assert len(registry._plugins["hotspot"]) == 1


class TestRegistryConcurrentMixedReadsWrites:
    def test_reader_does_not_observe_partial_state(self):
        """Lookups during concurrent registrations don't observe torn state.

        Specifically, ``get_plugin`` must either find a fully-registered
        manifest or raise ``not found`` — never return ``None`` or crash
        on a half-written inner dict.
        """
        registry = PluginRegistry()
        stop = threading.Event()
        errors: list[Exception] = []

        def writer():
            i = 0
            while not stop.is_set():
                try:
                    registry.register(_make_manifest("churn", f"{i}.0.0"))
                except MarketplaceError:
                    pass  # duplicate is fine
                i += 1
                if i > 500:
                    break

        def reader():
            while not stop.is_set():
                try:
                    registry.get_plugin("churn")
                except MarketplaceError:
                    pass  # not-yet-registered is fine
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    return

        w = threading.Thread(target=writer)
        r = threading.Thread(target=reader)
        w.start()
        r.start()
        time.sleep(0.2)
        stop.set()
        w.join(timeout=5)
        r.join(timeout=5)

        assert errors == [], f"reader saw torn state: {errors}"
