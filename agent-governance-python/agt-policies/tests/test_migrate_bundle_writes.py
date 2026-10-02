# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A generated policy and its digest must be published together."""

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from agt.cli._migrate_resolution.build import _materialize_rego_bundle
from agt.cli._migrate_resolution.errors import ResolutionError


def test_digest_matches_bytes_written(tmp_path):
    bundle = _materialize_rego_bundle(tmp_path, [])
    actual = hashlib.sha256((bundle / "agt_legacy.rego").read_bytes()).hexdigest()
    assert (bundle / "agt_legacy.rego.sha256").read_text() == actual


def test_digest_write_failure_does_not_publish_policy(tmp_path, monkeypatch):
    for method in ("write_text", "write_bytes"):
        original = getattr(Path, method)

        def fail_digest(path, *args, _original=original, **kwargs):
            if path.name.endswith(".sha256"):
                raise OSError("injected digest failure")
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(Path, method, fail_digest)
    with pytest.raises(ResolutionError):
        _materialize_rego_bundle(tmp_path, [])
    assert not (tmp_path / "policy").exists()
    assert list(tmp_path.iterdir()) == []


def test_existing_bundle_is_preserved(tmp_path):
    bundle = tmp_path / "policy"
    bundle.mkdir()
    policy = bundle / "agt_legacy.rego"
    policy.write_bytes(b"existing policy")
    with pytest.raises(ResolutionError):
        _materialize_rego_bundle(tmp_path, [])
    assert policy.read_bytes() == b"existing policy"


def test_failed_publication_removes_staging(tmp_path, monkeypatch):
    def fail_rename(*args, **kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(Path, "rename", fail_rename)
    with pytest.raises(ResolutionError):
        _materialize_rego_bundle(tmp_path, [])
    assert list(tmp_path.iterdir()) == []


def test_directory_failure_is_a_migration_diagnostic(tmp_path, monkeypatch):
    def fail_mkdir(*args, **kwargs):
        raise PermissionError("injected directory failure")

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    with pytest.raises(ResolutionError, match="PermissionError") as error:
        _materialize_rego_bundle(tmp_path / "output", [])
    assert str(tmp_path / "output" / "policy") in error.value.detail
    assert "injected directory failure" not in error.value.detail


def test_concurrent_publication_has_one_complete_winner(tmp_path, monkeypatch):
    barrier = threading.Barrier(2)
    original = Path.rename

    def publish(path, target):
        barrier.wait(timeout=5)
        return original(path, target)

    monkeypatch.setattr(Path, "rename", publish)

    def write_bundle(name):
        try:
            return _materialize_rego_bundle(tmp_path, [{"name": name, "action": "deny"}])
        except ResolutionError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write_bundle, ["first", "second"]))
    assert sum(result is not None for result in results) == 1
    bundle = tmp_path / "policy"
    actual = hashlib.sha256((bundle / "agt_legacy.rego").read_bytes()).hexdigest()
    assert (bundle / "agt_legacy.rego.sha256").read_text() == actual
    assert list(tmp_path.iterdir()) == [bundle]
