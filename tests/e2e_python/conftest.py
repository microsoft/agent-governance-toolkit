# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared configuration for the Python governance E2E suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Rewrite asserts in the shared assertion helpers for readable failures.
pytest.register_assert_rewrite("support.assertions")


@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    configured = os.environ.get("AGT_E2E_ARTIFACT_DIR")
    return Path(configured) if configured else tmp_path / "artifacts" / "ollama"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--agt-e2e-log-model-io",
        choices=("off", "summary", "full"),
        default="summary",
        help="Log model requests/responses: off, summary with truncation, or full.",
    )
    parser.addoption(
        "--agt-e2e-log-live",
        choices=("on", "off"),
        default="on",
        help="Show E2E logs live in pytest output.",
    )
    parser.addoption(
        "--agt-e2e-log-format",
        choices=("compact", "pretty"),
        default="pretty",
        help="Format model request/response log payloads.",
    )
    parser.addoption(
        "--agt-e2e-log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
        help="Live pytest log level for E2E logs.",
    )
    parser.addoption(
        "--agt-e2e-log-text-limit",
        type=int,
        default=1000,
        help="Maximum characters for each logged string in summary mode.",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e_python: Python governance E2E scenario")
    config.addinivalue_line("markers", "ollama: requires a local Ollama server")
    log_mode = str(config.getoption("--agt-e2e-log-model-io"))
    log_format = str(config.getoption("--agt-e2e-log-format"))
    log_text_limit = int(config.getoption("--agt-e2e-log-text-limit"))
    if log_text_limit < 1:
        raise pytest.UsageError("--agt-e2e-log-text-limit must be greater than 0")

    from support import configure_model_logging

    configure_model_logging(log_mode, log_text_limit, log_format)
    log_live = str(config.getoption("--agt-e2e-log-live")) == "on"
    config.option.log_cli = log_live
    config.option.log_cli_level = (
        str(config.getoption("--agt-e2e-log-level")) if log_live else "CRITICAL"
    )
    config.option.log_cli_format = "%(levelname)s %(name)s: %(message)s"
