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

    def test_custom_args(self):
        args = _build_arg_parser().parse_args(
            ["--host", "0.0.0.0", "--port", "9000", "--policy-dir", "/tmp/p"]
        )
        assert args.host == "0.0.0.0"
        assert args.port == 9000
        assert args.policy_dir == "/tmp/p"

    def test_port_must_be_int(self):
        with pytest.raises(SystemExit):
            _build_arg_parser().parse_args(["--port", "notanumber"])


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
        monkeypatch.setattr(
            "agentmesh.engine_api.app.create_app", lambda policy_dir=None: sentinel
        )

        main(["--host", "127.0.0.1", "--port", "1234"])
        assert captured["app"] is sentinel
        assert captured["host"] == "127.0.0.1"
        assert captured["port"] == 1234
