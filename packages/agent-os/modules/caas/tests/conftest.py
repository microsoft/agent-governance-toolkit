# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
pytest configuration and fixtures for Context-as-a-Service tests.
"""
import sys
from pathlib import Path

# Add parent directory to path so we can import caas
sys.path.insert(0, str(Path(__file__).parent.parent))
