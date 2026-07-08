# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the module CLI entry point (argument parsing and main wiring)."""

from __future__ import annotations

import pytest

from agentmesh.engine_api.__main__ import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    _build_arg_parser,
    main,
)


class TestArgParser:
    def test_loopback_default_bind(self):
        args = _build_arg_parser().parse_args([])
        assert args.host == DEFAULT_HOST == "127.0.0.1"
        assert args.port == DEFAULT_PORT == 8080
        assert args.policy_dir is None
        assert args.enable_policy_save is False

    def test_custom_args(self):
        args = _build_arg_parser().parse_args(
            ["--host", "0.0.0.0", "--port", "9000", "--policy-dir", "/tmp/p"]
        )
        assert args.host == "0.0.0.0"
        assert args.port == 9000
        assert args.policy_dir == "/tmp/p"

    def test_port_must_be_int(self):
        with pytest.raises(SystemExit):
            _build_arg_parser().parse_args(["--port", "not-a-number"])

    def test_enable_policy_save_flag(self):
        assert _build_arg_parser().parse_args(["--enable-policy-save"]).enable_policy_save is True


class TestMain:
    def test_main_invokes_uvicorn_with_app(self, monkeypatch):
        pytest.importorskip("fastapi")
        pytest.importorskip("uvicorn")
        import uvicorn

        captured = {}

        def _fake_run(app, host, port):
            captured["app"] = app
            captured["host"] = host
            captured["port"] = port

        monkeypatch.setattr(uvicorn, "run", _fake_run)

        sentinel = object()

        def _fake_create_app(policy_dir=None, enable_policy_save=None):
            captured["policy_dir"] = policy_dir
            captured["enable_policy_save"] = enable_policy_save
            return sentinel

        monkeypatch.setattr("agentmesh.engine_api.app.create_app", _fake_create_app)

        main(["--host", "127.0.0.1", "--port", "1234"])
        assert captured["app"] is sentinel
        assert captured["host"] == "127.0.0.1"
        assert captured["port"] == 1234
        # No --enable-policy-save flag -> None, so create_app defers to the env var.
        assert captured["enable_policy_save"] is None

    def test_main_passes_enable_policy_save_when_flag_set(self, monkeypatch):
        pytest.importorskip("fastapi")
        pytest.importorskip("uvicorn")
        import uvicorn

        captured = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, host, port: None)

        def _fake_create_app(policy_dir=None, enable_policy_save=None):
            captured["enable_policy_save"] = enable_policy_save
            return object()

        monkeypatch.setattr("agentmesh.engine_api.app.create_app", _fake_create_app)

        main(["--enable-policy-save"])
        assert captured["enable_policy_save"] is True
