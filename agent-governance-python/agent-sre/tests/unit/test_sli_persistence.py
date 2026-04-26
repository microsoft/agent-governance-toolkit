# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SLI persistence backends and CalibrationDeltaSLI."""

from __future__ import annotations

import time
import threading

import pytest

from agent_sre.slo.indicators import (
    CalibrationDeltaSLI,
    PolicyCompliance,
    TaskSuccessRate,
    TimeWindow,
)
from agent_sre.slo.persistence import (
    InMemoryMeasurementStore,
    SQLiteMeasurementStore,
    _validate_db_path,
)


# ---------------------------------------------------------------------------
# InMemoryMeasurementStore
# ---------------------------------------------------------------------------


class TestInMemoryMeasurementStore:
    def test_append_and_query(self) -> None:
        store = InMemoryMeasurementStore()
        t = time.time()
        store.append("test_sli", 0.95, t, {"target": 0.99})
        rows = store.query("test_sli", t - 1)
        assert len(rows) == 1
        assert rows[0].value == pytest.approx(0.95)

    def test_query_respects_since_cutoff(self) -> None:
        store = InMemoryMeasurementStore()
        old_ts = time.time() - 3700  # over 1 h ago
        new_ts = time.time()
        store.append("sli", 0.80, old_ts, {})
        store.append("sli", 0.90, new_ts, {})
        rows = store.query("sli", time.time() - 3600)
        assert len(rows) == 1
        assert rows[0].value == pytest.approx(0.90)

    def test_query_filters_by_name(self) -> None:
        store = InMemoryMeasurementStore()
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        assert len(store.query("alpha", 0)) == 1
        assert len(store.query("beta", 0)) == 1

    def test_clear_by_name(self) -> None:
        store = InMemoryMeasurementStore()
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        store.clear("alpha")
        assert store.query("alpha", 0) == []
        assert len(store.query("beta", 0)) == 1

    def test_clear_all(self) -> None:
        store = InMemoryMeasurementStore()
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        store.clear()
        assert store.query("alpha", 0) == []
        assert store.query("beta", 0) == []

    def test_thread_safety_concurrent_appends(self) -> None:
        """Concurrent appends must not corrupt internal state."""
        store = InMemoryMeasurementStore()
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                for _ in range(50):
                    store.append("sli", float(idx), time.time(), {})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(store.query("sli", 0)) == 400  # 8 threads × 50 appends


# ---------------------------------------------------------------------------
# SQLiteMeasurementStore
# ---------------------------------------------------------------------------


class TestSQLiteMeasurementStore:
    @pytest.fixture()
    def store(self) -> SQLiteMeasurementStore:
        return SQLiteMeasurementStore(db_path=":memory:")

    def test_append_and_query(self, store: SQLiteMeasurementStore) -> None:
        t = time.time()
        store.append("task_success_rate", 0.98, t, {"target": 0.995})
        rows = store.query("task_success_rate", t - 1)
        assert len(rows) == 1
        assert rows[0].value == pytest.approx(0.98)
        assert rows[0].metadata["target"] == pytest.approx(0.995)

    def test_query_since_filters_old_measurements(self, store: SQLiteMeasurementStore) -> None:
        old = time.time() - 86500  # >24 h ago
        now = time.time()
        store.append("sli", 0.70, old, {})
        store.append("sli", 0.95, now, {})
        rows = store.query("sli", time.time() - 86400)
        assert len(rows) == 1
        assert rows[0].value == pytest.approx(0.95)

    def test_query_by_name_isolation(self, store: SQLiteMeasurementStore) -> None:
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        assert len(store.query("alpha", 0)) == 1
        assert store.query("alpha", 0)[0].name == "alpha"

    def test_clear_by_name(self, store: SQLiteMeasurementStore) -> None:
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        store.clear("alpha")
        assert store.query("alpha", 0) == []
        assert len(store.query("beta", 0)) == 1

    def test_clear_all(self, store: SQLiteMeasurementStore) -> None:
        t = time.time()
        store.append("alpha", 1.0, t, {})
        store.append("beta", 0.5, t, {})
        store.clear()
        assert store.query("alpha", 0) == []
        assert store.query("beta", 0) == []

    def test_metadata_roundtrip(self, store: SQLiteMeasurementStore) -> None:
        t = time.time()
        meta = {"target": 0.99, "extra": "value", "nested": False}
        store.append("sli", 0.98, t, meta)
        rows = store.query("sli", 0)
        assert rows[0].metadata == meta

    def test_results_in_ascending_order(self, store: SQLiteMeasurementStore) -> None:
        base = time.time()
        for i in range(5):
            store.append("sli", float(i), base + i, {})
        rows = store.query("sli", 0)
        timestamps = [r.timestamp for r in rows]
        assert timestamps == sorted(timestamps)

    def test_invalid_uri_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid db_path"):
            _validate_db_path("http://malicious.example.com/db")

    def test_ftp_uri_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid db_path"):
            _validate_db_path("ftp://evil.server/db.sqlite")

    def test_memory_path_accepted(self) -> None:
        assert _validate_db_path(":memory:") == ":memory:"

    def test_file_uri_etc_passwd_raises(self) -> None:
        """file:///etc/passwd should be rejected as outside safe directories."""
        with pytest.raises(ValueError, match="Invalid db_path|outside allowed"):
            _validate_db_path("file:///etc/passwd")

    def test_file_uri_inside_home_accepted(self, tmp_path: object) -> None:
        """file:// URI resolving inside home dir should be accepted."""
        import pathlib
        home = pathlib.Path.home()
        # Construct a path under home that looks like a file:// URI
        target = str(home / "sli_test.db")
        result = _validate_db_path(f"file://{target}")
        assert result == str(pathlib.Path(target).resolve())

    def test_remote_file_uri_raises(self) -> None:
        """file://hostname/path (remote) should be rejected."""
        with pytest.raises(ValueError, match="Invalid db_path|remote"):
            _validate_db_path("file://remotehost/path/to/db")

    def test_path_outside_safe_dirs_raises(self) -> None:
        """/var/log/syslog is outside home/tmp/cwd — should be rejected."""
        with pytest.raises(ValueError, match="Invalid db_path|outside allowed"):
            _validate_db_path("/var/log/syslog")

    def test_excessively_long_path_raises(self) -> None:
        """Paths > 4096 chars should be rejected."""
        long_path = "a" * 4097
        with pytest.raises(ValueError, match="exceeds"):
            _validate_db_path(long_path)

    def test_thread_safety_in_memory_store(self) -> None:
        """Concurrent appends to SQLiteMeasurementStore(:memory:) must not race."""
        import threading as _threading
        store = SQLiteMeasurementStore(db_path=":memory:")
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for i in range(50):
                    store.append("sli", float(i), float(i), {})
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [_threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"
        rows = store.query("sli", 0)
        assert len(rows) == 8 * 50


# ---------------------------------------------------------------------------
# SLI integration: SQLite store survives "restart" (re-open)
# ---------------------------------------------------------------------------


class TestSLIWithSQLiteStore:
    def test_measurements_survive_sli_recreation(self, tmp_path: object) -> None:
        db = str(tmp_path / "sli.db")  # type: ignore[operator]
        store1 = SQLiteMeasurementStore(db_path=db)
        sli1 = TaskSuccessRate(store=store1)
        sli1.record_task(success=True)
        sli1.record_task(success=True)
        sli1.record_task(success=False)

        # Simulate restart: new SLI instance, same db file
        store2 = SQLiteMeasurementStore(db_path=db)
        sli2 = TaskSuccessRate(store=store2)
        vals = sli2.values_in_window()
        assert len(vals) == 3, "Measurements should survive across SLI instances"

    def test_default_store_is_in_memory(self) -> None:
        sli = PolicyCompliance()
        assert isinstance(sli._store, InMemoryMeasurementStore)

    def test_sqlite_store_accepted(self) -> None:
        store = SQLiteMeasurementStore(db_path=":memory:")
        sli = PolicyCompliance(store=store)
        assert isinstance(sli._store, SQLiteMeasurementStore)


# ---------------------------------------------------------------------------
# CalibrationDeltaSLI
# ---------------------------------------------------------------------------


class TestCalibrationDeltaSLI:
    def test_perfect_calibration(self) -> None:
        sli = CalibrationDeltaSLI(target_delta=0.05)
        # 10 predictions at 0.8 confidence, 8 succeed → aggregate delta ≈ 0
        for i in range(10):
            sli.record_prediction(0.8, actual_success=(i < 8))
        delta = sli.current_value()
        assert delta is not None
        assert delta == pytest.approx(0.0, abs=0.01)

    def test_overconfident_calibration(self) -> None:
        sli = CalibrationDeltaSLI(target_delta=0.05)
        # Predict 0.9 but only 50% succeed → aggregate delta ≈ 0.4
        for i in range(10):
            sli.record_prediction(0.9, actual_success=(i < 5))
        delta = sli.current_value()
        assert delta is not None
        assert delta == pytest.approx(0.4, abs=0.02)

    def test_compliance_counts_at_or_below_target(self) -> None:
        sli = CalibrationDeltaSLI(target_delta=0.10)
        # Single prediction: 0.8 predicted, fails → delta = |0.8 - 0| = 0.8 → NOT compliant
        sli.record_prediction(0.8, actual_success=False)
        compliance = sli.compliance()
        assert compliance is not None
        # 0.8 > 0.10 target → 0% compliant
        assert compliance == pytest.approx(0.0)

    def test_compliance_well_calibrated_series(self) -> None:
        sli = CalibrationDeltaSLI(target_delta=0.10)
        # 10 predictions at 0.9, 9 succeed → aggregate delta converges to 0 → all compliant
        for i in range(10):
            sli.record_prediction(0.9, actual_success=(i < 9))
        compliance = sli.compliance()
        assert compliance is not None
        # Final aggregate delta ≈ 0 → all window measurements should be compliant
        assert compliance > 0.5

    def test_collect_returns_current_delta(self) -> None:
        sli = CalibrationDeltaSLI()
        # No predictions yet → collect() should return 0.0
        val = sli.collect()
        assert val.value == pytest.approx(0.0)

    def test_sqlite_backend_works(self) -> None:
        store = SQLiteMeasurementStore(db_path=":memory:")
        sli = CalibrationDeltaSLI(store=store)
        sli.record_prediction(0.8, actual_success=True)
        sli.record_prediction(0.8, actual_success=False)
        delta = sli.current_value()
        assert delta is not None
        assert 0.0 <= delta <= 1.0
