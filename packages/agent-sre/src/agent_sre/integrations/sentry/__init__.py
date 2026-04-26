# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sentry integration for Agent SRE.

Provides a lightweight exporter for incidents, SLO breaches, and exceptions.
"""

from agent_sre.integrations.sentry.exporter import SentryExporter

__all__ = ["SentryExporter"]
