# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security scanning module for agent governance.

This module provides security scanning capabilities for agent code and plugins:
- Secret detection (API keys, tokens, credentials)
- Dependency vulnerability scanning (CVEs)
- Dangerous code pattern detection
- Security exemption management

Example:
    from agent_compliance.security import scan_plugin_security

    exit_code, error_msg = scan_plugin_security(
        plugin_dir=Path("plugins/my-plugin"),
        plugin_name="my-plugin",
        verbose=True
    )
"""

from .scanner import (
    SecurityFinding,
    SecurityScanner,
    format_security_report,
    scan_plugin_security,
)

__all__ = [
    "SecurityFinding",
    "SecurityScanner",
    "format_security_report",
    "scan_plugin_security",
]
