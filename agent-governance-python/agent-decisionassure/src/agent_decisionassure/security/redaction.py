# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Sensitive data redaction for traces and reports."""
import re
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass


@dataclass
class RedactionConfig:
    """Configuration for which fields to redact."""
    redact_ssn: bool = True
    redact_credit_card: bool = True
    redact_email: bool = True
    redact_phone: bool = True
    redact_custom_patterns: List[str] = None

    def __post_init__(self):
        if self.redact_custom_patterns is None:
            self.redact_custom_patterns = []


# Default patterns
DEFAULT_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
}


def redact(
    data: Union[Dict[str, Any], List[Any], str],
    config: Optional[RedactionConfig] = None,
) -> Union[Dict[str, Any], List[Any], str]:
    """
    Redact sensitive information from a trace, report, or string.

    Handles nested dictionaries and lists recursively.
    """
    if config is None:
        config = RedactionConfig()

    if isinstance(data, str):
        return _redact_string(data, config)
    elif isinstance(data, dict):
        return {k: redact(v, config) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact(item, config) for item in data]
    else:
        return data


def _redact_string(text: str, config: RedactionConfig) -> str:
    """Apply redaction patterns to a single string."""
    if not isinstance(text, str):
        return text

    # Apply built-in patterns
    if config.redact_ssn:
        text = re.sub(DEFAULT_PATTERNS["ssn"], "[REDACTED SSN]", text)
    if config.redact_credit_card:
        text = re.sub(DEFAULT_PATTERNS["credit_card"], "[REDACTED CREDIT CARD]", text)
    if config.redact_email:
        text = re.sub(DEFAULT_PATTERNS["email"], "[REDACTED EMAIL]", text)
    if config.redact_phone:
        text = re.sub(DEFAULT_PATTERNS["phone"], "[REDACTED PHONE]", text)

    # Custom patterns
    for pattern in config.redact_custom_patterns:
        text = re.sub(pattern, "[REDACTED CUSTOM]", text)

    return text


# Alias for backward compatibility (some tests may expect this function)
def redact_sensitive(data: Union[Dict[str, Any], List[Any], str]) -> Union[Dict[str, Any], List[Any], str]:
    """Redact sensitive data using default configuration."""
    return redact(data, RedactionConfig())