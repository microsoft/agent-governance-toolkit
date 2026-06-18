# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Scanner plugin architecture for agent discovery."""

from .base import BaseScanner, ScannerRegistry
from .config import ConfigScanner
from .github import GitHubScanner
from .process import ProcessScanner

__all__ = [
    "BaseScanner",
    "ScannerRegistry",
    "ProcessScanner",
    "GitHubScanner",
    "ConfigScanner",
]
