# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configurable, redacted logging for model request/response events."""

from __future__ import annotations

import json
import logging
import re
from typing import Any


logger = logging.getLogger("support")
MODEL_IO_LOG_MODE = "summary"
MODEL_IO_LOG_FORMAT = "pretty"
LOG_TEXT_LIMIT: int | None = 1_000


def configure_model_logging(mode: str, text_limit: int, log_format: str) -> None:
    global MODEL_IO_LOG_MODE, MODEL_IO_LOG_FORMAT, LOG_TEXT_LIMIT

    MODEL_IO_LOG_MODE = mode
    MODEL_IO_LOG_FORMAT = log_format
    LOG_TEXT_LIMIT = None if mode == "full" else text_limit


def log_model_event(event: str, scenario_id: str, details: dict[str, Any]) -> None:
    if MODEL_IO_LOG_MODE == "off":
        return
    payload = {"scenario_id": scenario_id, **redact_for_log(details)}
    serialized = json.dumps(
        payload,
        indent=2 if MODEL_IO_LOG_FORMAT == "pretty" else None,
        sort_keys=True,
    )
    separator = "\n" if MODEL_IO_LOG_FORMAT == "pretty" else " "
    logger.info("%s%s%s", event, separator, serialized)


def redact_for_log(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_for_log(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [redact_for_log(item) for item in value]
    if isinstance(value, str):
        return truncate_log_text(redact_log_text(value))
    return value


def redact_log_text(value: str) -> str:
    value = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED]", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[REDACTED]", value)
    return re.sub(r"\bsk-[A-Za-z0-9_-]{10,}\b", "[REDACTED]", value)


def truncate_log_text(value: str) -> str:
    if LOG_TEXT_LIMIT is None:
        return value
    if len(value) <= LOG_TEXT_LIMIT:
        return value
    return f"{value[:LOG_TEXT_LIMIT]}..."
