# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Allow running agent-sre as: python -m agent_sre"""
import sys

from agent_sre.cli.main import cli

sys.exit(cli())
